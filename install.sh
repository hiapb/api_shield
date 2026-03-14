#!/bin/bash

# ====================================================
# 项目：API 零信任矩阵网关系统
# 环境：Debian / Ubuntu
# ====================================================

set -u
set -E
set -o pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

BASE_DIR="/etc/nginx/api_shield"
ACME_DIR="/var/www/letsencrypt"

declare -a CLEANUP_FILES=()

trap '
    if [ ${#CLEANUP_FILES[@]} -gt 0 ]; then
        rm -f "${CLEANUP_FILES[@]}" 2>/dev/null
    fi
' EXIT INT TERM

function on_err() {
    local ec=$?
    local line=$1
    echo -e "\n${YELLOW}[系统哨兵] 追踪日志：引擎在第 ${line} 行命令返回了状态码 ${ec}。若非预期拦截，请关注。${NC}"
}
trap 'on_err $LINENO' ERR

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}致命错误：必须拥有 root 物理控制权。${NC}"
  exit 1
fi


# ==========================================
# 核心验证组件
# ==========================================
function validate_domain() {
    local regex="^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    [[ "$1" =~ $regex ]]
}

function validate_ipv4() {
    local regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    [[ "$1" =~ $regex ]] &&
    IFS='.' read -r i1 i2 i3 i4 <<< "$1" &&
    ((i1<=255 && i2<=255 && i3<=255 && i4<=255))
}

function validate_target() {
    local target="$1"
    local host port
    
    if [[ "$target" == *:* ]]; then
        host="${target%:*}"
        port="${target##*:}"
    else
        host="$target"
        port=""
    fi

    if ! validate_domain "$host" && ! validate_ipv4 "$host" && [[ "$host" != "localhost" ]]; then return 1; fi
    if [[ -n "$port" ]]; then
        if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then return 1; fi
    fi
    return 0
}

function validate_path() {
    local regex="^/[A-Za-z0-9._~/-]*$"
    [[ "$1" =~ $regex ]]
}

function validate_number() { 
    local regex="^[0-9]+$"
    [[ "$1" =~ $regex ]]
}

function escape_regex() {
    echo "$1" | sed 's/[.*+?()[\]{}|^$\\]/\\&/g'
}

function init_env() {
    local need_apt=0
    if ! command -v nginx >/dev/null 2>&1; then need_apt=1; fi
    if ! command -v certbot >/dev/null 2>&1; then need_apt=1; fi

    if [ $need_apt -eq 1 ]; then
        echo -e "${CYAN}正在自检并按需补齐底层组件...${NC}"
        apt-get update -qq
        apt-get install -y nginx certbot coreutils > /dev/null 2>&1
    fi
    
    rm -f /etc/nginx/sites-enabled/default
    systemctl enable nginx >/dev/null 2>&1
    systemctl start nginx >/dev/null 2>&1
    mkdir -p "$BASE_DIR" "$ACME_DIR"
}

function safe_reload() {
    if nginx -t > /dev/null 2>&1 && systemctl reload nginx > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

function rollback_domain_deploy() {
    local domain=$1
    echo -e "${YELLOW}事务回滚：正在清扫现场并吊销关联证书...${NC}"
    rm -f "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/$domain"
    rm -rf "$BASE_DIR/$domain"
    certbot delete --cert-name "$domain" --non-interactive > /dev/null 2>&1
    safe_reload || true 
}

function manage_blackhole() {
    local domain_dir=$1
    local has_root=0
    
    # 免疫空目录地板钉
    shopt -s nullglob
    local confs=("$domain_dir"/*.conf)
    shopt -u nullglob

    for f in "${confs[@]}"; do
        if grep -q "# META_TYPE: ROOT_ROUTE" "$f" 2>/dev/null; then
            has_root=1; break
        fi
    done

    if [ $has_root -eq 1 ]; then
        rm -f "$domain_dir/00_blackhole.conf"
    else
        cat > "$domain_dir/00_blackhole.conf" <<EOF
# META_TYPE: BLACKHOLE
location / {
    return 444;
}
EOF
    fi
}

function generate_proxy_block() {
    local api_path=$1
    local target_proto=$2
    local target_domain=$3
    local target_path=$4
    local save_path=$5

    local ssl_headers=""
    if [ "$target_proto" == "https" ]; then
        ssl_headers="proxy_ssl_server_name on;\n    proxy_ssl_name $target_domain;"
    fi

    local clean_target_path="$target_path"
    if [ "$target_path" != "/" ] && [ -n "$target_path" ]; then
        clean_target_path=$(echo "$target_path" | sed 's/\/$//')
    fi

    if [ "$api_path" == "/" ]; then
        local final_url="${target_proto}://${target_domain}"
        if [ -n "$clean_target_path" ] && [ "$clean_target_path" != "/" ]; then
            final_url="${target_proto}://${target_domain}${clean_target_path}/"
        else
            final_url="${target_proto}://${target_domain}/"
        fi

        cat > "$save_path" <<EOF
# META_TYPE: ROOT_ROUTE
# META_DISPLAY: / ===> $final_url
location / {
    proxy_pass $final_url;
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_connect_timeout 30s;
    proxy_read_timeout 120s;
}
EOF
    elif [ -z "$clean_target_path" ]; then
        local clean_api_path=$(echo "$api_path" | sed 's/\/$//')
        
        cat > "$save_path" <<EOF
# META_TYPE: SUB_ROUTE
# META_DISPLAY: ${clean_api_path}/ ===> ${target_proto}://${target_domain} (原样透传)
location ^~ ${clean_api_path}/ {
    proxy_pass ${target_proto}://${target_domain};
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_connect_timeout 30s;
}

location = ${clean_api_path} {
    rewrite ^(.*)\$ ${clean_api_path}/ permanent;
}
EOF
    else
        local clean_api_path=$(echo "$api_path" | sed 's/\/$//')
        local safe_regex_api=$(escape_regex "$clean_api_path")

        cat > "$save_path" <<EOF
# META_TYPE: SUB_ROUTE
# META_DISPLAY: ${clean_api_path}/ ===> ${target_proto}://${target_domain}${clean_target_path}/ (重写)
location ^~ ${clean_api_path}/ {
    rewrite ^${safe_regex_api}/(.*)\$ ${clean_target_path}/\$1 break;
    proxy_pass ${target_proto}://${target_domain};
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_connect_timeout 30s;
}

location = ${clean_api_path} {
    rewrite ^(.*)\$ ${clean_api_path}/ permanent;
}
EOF
    fi
}

function deploy_domain() {
    echo -e "\n${CYAN}--- 部署全新网关节点 ---${NC}"
    
    local MY_DOMAIN TARGET_DOMAIN API_PATH TARGET_PATH
    
    while true; do
        read -p "1. 请输入网关域名 (例 api.domain.com): " MY_DOMAIN
        if validate_domain "$MY_DOMAIN"; then break; fi
        echo -e "${RED}输入非法：请使用标准 RFC 域名。${NC}"
    done

    if [ -f "/etc/nginx/sites-available/$MY_DOMAIN" ]; then
        echo -e "${RED}该域名防线已存在，请在路由管理中追加。${NC}"; return
    fi

    echo -e "2. 目标源站协议选择:"
    echo "   [1] HTTP  (内网透传)"
    echo "   [2] HTTPS (外部反代)"
    local proto_choice TARGET_PROTO
    while true; do
        read -p "   请选择 (1/2): " proto_choice
        if [[ "$proto_choice" == "1" || "$proto_choice" == "2" ]]; then break; fi
    done
    TARGET_PROTO=$([ "$proto_choice" == "1" ] && echo "http" || echo "https")

    while true; do
        read -p "3. 请输入反代源站 (限 域名/IPv4/localhost[:port]): " TARGET_DOMAIN
        if validate_target "$TARGET_DOMAIN"; then break; fi
        echo -e "${RED}目标格式非法 (暂不支持 IPv6)。${NC}"
    done

    while true; do
        read -p "4. 请输入对外放行路径 (输入 / 为全量穿透): " API_PATH
        if validate_path "$API_PATH"; then break; fi
        echo -e "${RED}路径非法。${NC}"
    done

    read -p "5. 请输入后端真实映射路径 (直接回车保持原样透传): " TARGET_PATH
    if [ -n "$TARGET_PATH" ] && ! validate_path "$TARGET_PATH"; then
        echo -e "${YELLOW}映射路径非法，已强制降维至 [原样透传] 模式。${NC}"
        TARGET_PATH=""
    fi

    echo -e "6. 是否开启 User-Agent 嗅探拦截?"
    read -p "   [y/N] (默认关闭, 避免误伤合法代码调度): " ua_choice
    local UA_BLOCK=""
    if [[ "$ua_choice" =~ ^[Yy]$ ]]; then
        UA_BLOCK="if (\$http_user_agent ~* (curl|wget|python|java|go-http-client|nikto|nmap|zgrab|masscan)) { return 444; }"
    fi

    echo -e "${YELLOW}启动物理隔离验证签发流程 (Webroot)...${NC}"
    local TMP_CONF="/etc/nginx/sites-available/$MY_DOMAIN"
    
    cat > "$TMP_CONF" <<EOF
server {
    listen 80;
    server_name $MY_DOMAIN;
    location /.well-known/acme-challenge/ {
        root $ACME_DIR;
    }
    location / { return 404; }
}
EOF
    ln -sf "$TMP_CONF" /etc/nginx/sites-enabled/
    safe_reload || { echo -e "${RED}验证配置加载失败。${NC}"; rm -f "$TMP_CONF" "/etc/nginx/sites-enabled/$MY_DOMAIN"; return; }

    certbot certonly --webroot -w "$ACME_DIR" -d "$MY_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email > /dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}致命错误：ACME 握手失败，TLS 证书未能签发。${NC}"
        rollback_domain_deploy "$MY_DOMAIN"
        return
    fi

    mkdir -p "$BASE_DIR/$MY_DOMAIN"
    local SAFE_HASH=$(echo -n "$API_PATH" | sha256sum | awk '{print $1}' | cut -c 1-8)
    local PATH_CONF="$BASE_DIR/$MY_DOMAIN/route_${SAFE_HASH}.conf"

    generate_proxy_block "$API_PATH" "$TARGET_PROTO" "$TARGET_DOMAIN" "$TARGET_PATH" "$PATH_CONF"
    manage_blackhole "$BASE_DIR/$MY_DOMAIN"

    cat > "$TMP_CONF" <<EOF
server {
    listen 80;
    server_name $MY_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $MY_DOMAIN;
    client_max_body_size 500M;
    ssl_certificate /etc/letsencrypt/live/$MY_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$MY_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    $UA_BLOCK
    include $BASE_DIR/$MY_DOMAIN/*.conf;
}
EOF
    
    if safe_reload; then
        local meta_disp=$(grep "^# META_DISPLAY:" "$PATH_CONF" | sed 's/^# META_DISPLAY:[[:space:]]*//' 2>/dev/null)
        echo -e "${GREEN}网关节点底座铸造完毕。${NC}"
        [ -n "$meta_disp" ] && echo -e "首条生效链路：${YELLOW}${meta_disp}${NC}"
    else
        echo -e "${RED}底层配置加载失败，启动全局回滚...${NC}"
        rollback_domain_deploy "$MY_DOMAIN"
    fi
}

function manage_paths() {
    echo -e "\n${CYAN}--- 内部路由矩阵编排 ---${NC}"
    
    shopt -s nullglob
    local dir_list=("$BASE_DIR"/*)
    shopt -u nullglob
    
    local domains=()
    for dir in "${dir_list[@]}"; do
        if [ -d "$dir" ]; then domains+=("$(basename "$dir")"); fi
    done

    if [ ${#domains[@]} -eq 0 ]; then echo -e "无活动节点。"; return; fi

    for i in "${!domains[@]}"; do echo "$((i+1)). ${domains[$i]}"; done
    local d_choice
    read -p "选择节点 (0 返回): " d_choice
    if ! validate_number "$d_choice" || (( d_choice < 0 || d_choice > ${#domains[@]} )); then return; fi
    if [ "$d_choice" == "0" ]; then return; fi
    
    local SELECT_DOMAIN="${domains[$((d_choice-1))]}"
    local DOMAIN_DIR="$BASE_DIR/$SELECT_DOMAIN"

    echo -e "\n当前操作域: ${GREEN}$SELECT_DOMAIN${NC}"
    echo "1. 挂载新路由"
    echo "2. 物理截断路由"
    local op_choice
    read -p "选择操作: " op_choice

    if [ "$op_choice" == "1" ]; then
        echo -e "   [1] HTTP\n   [2] HTTPS"
        local proto_choice TARGET_PROTO
        while true; do
            read -p "选择协议 (1/2): " proto_choice
            if [[ "$proto_choice" == "1" || "$proto_choice" == "2" ]]; then break; fi
        done
        TARGET_PROTO=$([ "$proto_choice" == "1" ] && echo "http" || echo "https")

        local TARGET_DOMAIN API_PATH TARGET_PATH
        while true; do read -p "反代源站 (限 域名/IPv4/localhost): " TARGET_DOMAIN; if validate_target "$TARGET_DOMAIN"; then break; fi; done
        while true; do read -p "对外放行路径: " API_PATH; if validate_path "$API_PATH"; then break; fi; done
        
        read -p "后端真实映射路径 (直接回车保持透传): " TARGET_PATH
        if [ -n "$TARGET_PATH" ] && ! validate_path "$TARGET_PATH"; then TARGET_PATH=""; fi

        local SAFE_HASH=$(echo -n "$API_PATH" | sha256sum | awk '{print $1}' | cut -c 1-8)
        local PATH_CONF="$DOMAIN_DIR/route_${SAFE_HASH}.conf"
        
        local is_overwrite=0
        if [ -f "$PATH_CONF" ]; then
            is_overwrite=1
            cp "$PATH_CONF" "${PATH_CONF}.bak"
            CLEANUP_FILES+=("${PATH_CONF}.bak")
        fi

        generate_proxy_block "$API_PATH" "$TARGET_PROTO" "$TARGET_DOMAIN" "$TARGET_PATH" "$PATH_CONF"
        manage_blackhole "$DOMAIN_DIR"

        if safe_reload; then
            local meta_disp=$(grep "^# META_DISPLAY:" "$PATH_CONF" | sed 's/^# META_DISPLAY:[[:space:]]*//' 2>/dev/null)
            echo -e "${GREEN}路由链路贯通成功。${NC}"
            [ -n "$meta_disp" ] && echo -e "当前生效链路：${YELLOW}${meta_disp}${NC}"
            
            # 状态稳定，主动清理本次操作的备份文件
            if [ $is_overwrite -eq 1 ]; then rm -f "${PATH_CONF}.bak"; fi
        else
            echo -e "${RED}路由注入失败，启动对称防抱死恢复...${NC}"
            if [ $is_overwrite -eq 1 ]; then
                mv "${PATH_CONF}.bak" "$PATH_CONF"
            else
                rm -f "$PATH_CONF"
            fi
            manage_blackhole "$DOMAIN_DIR"
            safe_reload 
        fi

    elif [ "$op_choice" == "2" ]; then
        shopt -s nullglob
        local conf_list=("$DOMAIN_DIR"/*.conf)
        shopt -u nullglob
        
        local path_files=()
        for f in "${conf_list[@]}"; do
            [[ "$(basename "$f")" != "00_blackhole.conf" ]] && [ -f "$f" ] && path_files+=("$f")
        done

        if [ ${#path_files[@]} -eq 0 ]; then echo "暂无自定义路由。"; return; fi

        for i in "${!path_files[@]}"; do
            local meta_disp=$(grep "^# META_DISPLAY:" "${path_files[$i]}" | sed 's/^# META_DISPLAY:[[:space:]]*//' 2>/dev/null)
            if [ -n "$meta_disp" ]; then
                echo "$((i+1)). $meta_disp"
            else
                echo "$((i+1)). [未识别配置] $(basename "${path_files[$i]}")"
            fi
        done
        
        local p_choice
        read -p "选择抹除序号 (0 取消): " p_choice
        if ! validate_number "$p_choice" || (( p_choice < 0 || p_choice > ${#path_files[@]} )); then return; fi
        if [ "$p_choice" == "0" ]; then return; fi

        local DEL_FILE="${path_files[$((p_choice-1))]}"
        
        cp "$DEL_FILE" "${DEL_FILE}.bak"
        CLEANUP_FILES+=("${DEL_FILE}.bak")
        rm -f "$DEL_FILE"
        manage_blackhole "$DOMAIN_DIR"
        
        if safe_reload; then
            rm -f "${DEL_FILE}.bak" # 成功则即时清理废弃物
            echo -e "${YELLOW}路由链路已物理截断。${NC}"
        else
            echo -e "${RED}引擎重载受阻，启动恢复程序...${NC}"
            mv "${DEL_FILE}.bak" "$DEL_FILE"
            manage_blackhole "$DOMAIN_DIR"
            safe_reload
        fi
    fi
}

function list_status() {
    echo -e "\n${CYAN}====== 路由透视全景图 ======${NC}"
    local count=0
    
    shopt -s nullglob
    local dir_list=("$BASE_DIR"/*)
    shopt -u nullglob
    
    for dir in "${dir_list[@]}"; do
        if [ -d "$dir" ]; then
            local domain=$(basename "$dir")
            echo -e "🌐 【网关节点】: ${GREEN}$domain${NC}"
            
            shopt -s nullglob
            local conf_list=("$dir"/*.conf)
            shopt -u nullglob
            
            for conf in "${conf_list[@]}"; do
                if grep -q "# META_TYPE: BLACKHOLE" "$conf" 2>/dev/null; then
                    echo -e "      ↳ ${RED}[底座防御] 兜底黑洞已激活 (拦截未知请求)${NC}"
                else
                    local meta=$(grep "^# META_DISPLAY:" "$conf" | sed 's/^# META_DISPLAY:[[:space:]]*//' 2>/dev/null)
                    if [ -n "$meta" ]; then
                        echo -e "      ↳ [链路] ${YELLOW}${meta}${NC}"
                    fi
                fi
            done
            echo "----------------------------------------------"
            ((count++))
        fi
    done
    if [ $count -eq 0 ]; then echo "全网静默，无活动状态节点。"; fi
}

function delete_domain() {
    echo -e "\n${CYAN}--- 彻底抹除节点 ---${NC}"
    
    shopt -s nullglob
    local dir_list=("$BASE_DIR"/*)
    shopt -u nullglob
    
    local domains=()
    for dir in "${dir_list[@]}"; do
        if [ -d "$dir" ]; then domains+=("$(basename "$dir")"); fi
    done
    
    if [ ${#domains[@]} -eq 0 ]; then return; fi

    for i in "${!domains[@]}"; do echo "$((i+1)). ${domains[$i]}"; done
    local choice
    read -p "选择摧毁序号 (0 取消): " choice
    if ! validate_number "$choice" || (( choice < 0 || choice > ${#domains[@]} )); then return; fi
    if [ "$choice" == "0" ]; then return; fi

    local DEL_DOMAIN="${domains[$((choice-1))]}"
    rollback_domain_deploy "$DEL_DOMAIN"
    echo -e "${GREEN}节点 [$DEL_DOMAIN] 的所有痕迹已从底座抹去。${NC}"
}

init_env
clear
while true; do
    echo -e "\n=============================================="
    echo -e "      ${GREEN}API 零信任矩阵网关 ${NC}"
    echo -e "=============================================="
    echo "  1. 部署全新网关防线"
    echo "  2. 管理内部路由矩阵"
    echo "  3. 视察全景透视状态"
    echo "  4. 彻底摧毁网关节点"
    echo "  0. 安全退出"
    echo "----------------------------------------------"
    read -p "请输入指令: " menu_choice

    case $menu_choice in
        1) deploy_domain ;;
        2) manage_paths ;;
        3) list_status ;;
        4) delete_domain ;;
        0) echo -e "${GREEN}控制权已交还。${NC}\n"; exit 0 ;;
        *) echo -e "${RED}非法指令。${NC}" ;;
    esac
done
