#!/bin/bash

# ====================================================
# 项目：API 零信任流量护城河 (含隐蔽路径映射版)
# 环境：Debian / Ubuntu
# ====================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

BASE_DIR="/etc/nginx/api_shield"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}严重错误：必须使用 root 权限运行本系统。${NC}"
  exit 1
fi

function init_env() {
    if ! command -v nginx >/dev/null 2>&1 || ! command -v certbot >/dev/null 2>&1; then
        echo -e "${CYAN}正在初始化底层依赖环境...${NC}"
        apt-get update -qq
        apt-get install -y nginx certbot python3-certbot-nginx > /dev/null 2>&1
        rm -f /etc/nginx/sites-enabled/default
        systemctl enable nginx
        systemctl start nginx
    fi
    mkdir -p "$BASE_DIR"
}

function safe_reload() {
    nginx -t > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo -e "${GREEN}底层引擎已热重载，配置生效。${NC}"
        return 0
    else
        echo -e "${RED}异常拦截：Nginx 语法自检失败，已放弃重载以保护现有业务。${NC}"
        return 1
    fi
}

function deploy_domain() {
    echo -e "\n${CYAN}--- 部署全新网关节点 (含首条路由) ---${NC}"
    
    # 1. 捕获自身域名
    while true; do
        read -p "请输入新的网关域名 (例 api.domain.com): " MY_DOMAIN
        MY_DOMAIN=$(echo "$MY_DOMAIN" | tr -d ' ')
        if [ -n "$MY_DOMAIN" ]; then break; fi
        echo -e "${RED}域名不可为空。${NC}"
    done

    if [ -f "/etc/nginx/sites-available/$MY_DOMAIN" ]; then
        echo -e "${RED}该域名已存在。若要添加新路径，请使用主菜单的 [管理路径暗门] 功能。${NC}"
        return
    fi

    # 2. 捕获目标源站
    while true; do
        read -p "请输入反代的目标源站 (例 site.domain.com): " TARGET_DOMAIN
        TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | tr -d ' ')
        if [ -n "$TARGET_DOMAIN" ]; then break; fi
        echo -e "${RED}目标源站不可为空。${NC}"
    done

    # 3. 捕获放行路径
    while true; do
        read -p "请输入对外的 API 放行路径 (例 /v1): " API_PATH
        API_PATH=$(echo "$API_PATH" | tr -d ' ')
        if [ -n "$API_PATH" ]; then break; fi
        echo -e "${RED}放行路径不可为空。${NC}"
    done

    # 4. [新增核心逻辑] 捕获隐蔽映射路径
    read -p "请输入后端的真实隐蔽路径 (直接回车则保持原样，例 /xxx/v1): " TARGET_PATH
    TARGET_PATH=$(echo "$TARGET_PATH" | tr -d ' ')
    
    # 组装最终的 Proxy URL
    if [ -z "$TARGET_PATH" ]; then
        PROXY_URL="https://$TARGET_DOMAIN"
    else
        if [[ "$TARGET_PATH" != /* ]]; then
            TARGET_PATH="/$TARGET_PATH"
        fi
        PROXY_URL="https://$TARGET_DOMAIN$TARGET_PATH"
    fi

    echo -e "${YELLOW}参数捕获完毕。正在申请 SSL 证书...${NC}"
    TMP_CONF="/etc/nginx/sites-available/$MY_DOMAIN"
    cat > "$TMP_CONF" <<EOF
server {
    listen 80;
    server_name $MY_DOMAIN;
    location / { return 200 'challenge_ready'; }
}
EOF
    ln -sf "$TMP_CONF" /etc/nginx/sites-enabled/
    systemctl reload nginx

    certbot --nginx -d "$MY_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo -e "${RED}证书签发失败，请检查 DNS 解析。${NC}"
        rm -f "$TMP_CONF" /etc/nginx/sites-enabled/"$MY_DOMAIN"
        systemctl reload nginx
        return
    fi

    # 构建矩阵基座与首条路径碎片
    mkdir -p "$BASE_DIR/$MY_DOMAIN"
    SAFE_NAME=$(echo "$API_PATH" | sed 's/\//_/g')
    PATH_CONF="$BASE_DIR/$MY_DOMAIN/${SAFE_NAME}.conf"

    cat > "$PATH_CONF" <<EOF
location ^~ $API_PATH {
    proxy_pass $PROXY_URL;
    proxy_set_header Host $TARGET_DOMAIN;
    proxy_ssl_server_name on;
    proxy_ssl_name $TARGET_DOMAIN;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_connect_timeout 15s;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
    proxy_buffering off;
    chunked_transfer_encoding on;
}
EOF

    cat > "$TMP_CONF" <<EOF
server {
    listen 80;
    server_name $MY_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $MY_DOMAIN;

    client_max_body_size 100M;
    ssl_certificate /etc/letsencrypt/live/$MY_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$MY_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    if (\$http_user_agent ~* (curl|wget|python|java|go-http-client|nikto|nmap|zgrab|masscan)) {
        return 444; 
    }

    include $BASE_DIR/$MY_DOMAIN/*.conf;

    location / {
        return 444;
    }
}
EOF
    
    if safe_reload; then
        echo -e "${GREEN}部署成功！${NC}"
        echo -e "访问链路已打通: ${YELLOW}https://$MY_DOMAIN$API_PATH${NC}  ====>  ${CYAN}$PROXY_URL${NC}"
    else
        rm -f "$TMP_CONF" /etc/nginx/sites-enabled/"$MY_DOMAIN"
        rm -rf "$BASE_DIR/$MY_DOMAIN"
        systemctl reload nginx
    fi
}

function manage_paths() {
    echo -e "\n${CYAN}--- 管理路径暗门 ---${NC}"
    local domains=()
    for dir in "$BASE_DIR"/*; do
        if [ -d "$dir" ]; then
            domains+=("$(basename "$dir")")
        fi
    done

    if [ ${#domains[@]} -eq 0 ]; then
        echo -e "系统暂无受保护的域名。"; return
    fi

    echo "选择操作目标:"
    for i in "${!domains[@]}"; do
        echo "$((i+1)). ${domains[$i]}"
    done
    echo "0. 返回主菜单"
    
    read -p "请输入序号: " d_choice
    if [ "$d_choice" == "0" ]; then return; fi
    if [[ ! "$d_choice" =~ ^[0-9]+$ ]] || [ "$d_choice" -lt 1 ] || [ "$d_choice" -gt "${#domains[@]}" ]; then
        echo -e "${RED}输入无效。${NC}"; return
    fi
    
    local SELECT_DOMAIN="${domains[$((d_choice-1))]}"
    local DOMAIN_DIR="$BASE_DIR/$SELECT_DOMAIN"

    echo -e "\n当前操作域: ${GREEN}$SELECT_DOMAIN${NC}"
    echo "1. 为该网关【新增】其他穿透路径"
    echo "2. 将该网关的某条路径【物理抹除】"
    echo "0. 返回主菜单"
    read -p "请输入序号: " op_choice

    if [ "$op_choice" == "1" ]; then
        local existing_conf=$(ls "$DOMAIN_DIR"/*.conf 2>/dev/null | head -n 1)
        if [ -n "$existing_conf" ]; then
            TARGET_DOMAIN=$(grep "proxy_set_header Host" "$existing_conf" | awk '{print $4}' | tr -d ';')
            echo -e "${YELLOW}已自动锁定目标源站: ${CYAN}$TARGET_DOMAIN${NC}"
        else
            while true; do
                read -p "未找到存量路由配置，请重新输入目标源站: " TARGET_DOMAIN
                TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | tr -d ' ')
                if [ -n "$TARGET_DOMAIN" ]; then break; fi
            done
        fi

        while true; do
            read -p "请输入对外新增的 API 放行路径 (例 /v2/data): " API_PATH
            API_PATH=$(echo "$API_PATH" | tr -d ' ')
            if [ -n "$API_PATH" ]; then break; fi
        done

        # [新增核心逻辑] 捕获隐蔽映射路径
        read -p "请输入后端的真实隐蔽路径 (直接回车保持原样，例 /core/v2): " TARGET_PATH
        TARGET_PATH=$(echo "$TARGET_PATH" | tr -d ' ')

        if [ -z "$TARGET_PATH" ]; then
            PROXY_URL="https://$TARGET_DOMAIN"
        else
            if [[ "$TARGET_PATH" != /* ]]; then
                TARGET_PATH="/$TARGET_PATH"
            fi
            PROXY_URL="https://$TARGET_DOMAIN$TARGET_PATH"
        fi

        SAFE_NAME=$(echo "$API_PATH" | sed 's/\//_/g')
        PATH_CONF="$DOMAIN_DIR/${SAFE_NAME}.conf"

        cat > "$PATH_CONF" <<EOF
location ^~ $API_PATH {
    proxy_pass $PROXY_URL;
    proxy_set_header Host $TARGET_DOMAIN;
    proxy_ssl_server_name on;
    proxy_ssl_name $TARGET_DOMAIN;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_connect_timeout 15s;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
    proxy_buffering off;
    chunked_transfer_encoding on;
}
EOF
        if safe_reload; then
            echo -e "${GREEN}路径 [$API_PATH] 成功打通，已暗中映射至 [$PROXY_URL]。${NC}"
        else
            rm -f "$PATH_CONF"
            systemctl reload nginx
        fi

    elif [ "$op_choice" == "2" ]; then
        local path_files=()
        for f in "$DOMAIN_DIR"/*.conf; do
            [ -f "$f" ] && path_files+=("$f")
        done

        if [ ${#path_files[@]} -eq 0 ]; then
            echo "该域名下暂无开放路径。"; return
        fi

        echo -e "\n当前挂载的路径矩阵:"
        for i in "${!path_files[@]}"; do
            local p_val=$(grep "location \^~" "${path_files[$i]}" | awk '{print $3}')
            local t_val=$(grep "proxy_pass" "${path_files[$i]}" | awk '{print $2}' | tr -d ';')
            echo "$((i+1)). [网关入口] $p_val  ===>  [源站底座] $t_val"
        done
        echo "0. 返回主菜单"
        
        read -p "请输入要抹除的序号: " p_choice
        if [ "$p_choice" == "0" ]; then return; fi
        if [[ ! "$p_choice" =~ ^[0-9]+$ ]] || [ "$p_choice" -lt 1 ] || [ "$p_choice" -gt "${#path_files[@]}" ]; then
            echo -e "${RED}输入无效。${NC}"; return
        fi

        local DEL_FILE="${path_files[$((p_choice-1))]}"
        rm -f "$DEL_FILE"
        echo -e "${YELLOW}已切断该路由链路，正在热重载...${NC}"
        safe_reload
    fi
}

function list_status() {
    echo -e "\n${CYAN}====== 全网链路透视矩阵 ======${NC}"
    local count=0
    for dir in "$BASE_DIR"/*; do
        if [ -d "$dir" ]; then
            local domain=$(basename "$dir")
            echo -e "🌐 【主网关】: ${GREEN}$domain${NC}"
            local has_path=0
            for conf in "$dir"/*.conf; do
                if [ -f "$conf" ]; then
                    local p_val=$(grep "location \^~" "$conf" | awk '{print $3}')
                    local t_val=$(grep "proxy_pass" "$conf" | awk '{print $2}' | tr -d ';')
                    echo -e "      ↳ [入口] ${YELLOW}${p_val}${NC}  ======>  [伪装穿透至] ${CYAN}${t_val}${NC}"
                    has_path=1
                fi
            done
            if [ $has_path -eq 0 ]; then
                echo -e "      ↳ ${RED}[空洞] 当前无任何路由，外部访问全面阻断 (444丢弃)${NC}"
            fi
            echo "----------------------------------------------"
            ((count++))
        fi
    done
    if [ "$count" -eq 0 ]; then echo "当前处于物理隔离状态，无任何网关节点。"; fi
}

function delete_domain() {
    echo -e "\n${CYAN}--- 摧毁域名基地 ---${NC}"
    local domains=()
    for dir in "$BASE_DIR"/*; do
        if [ -d "$dir" ]; then
            domains+=("$(basename "$dir")")
        fi
    done

    if [ ${#domains[@]} -eq 0 ]; then
        echo "系统暂无可摧毁的节点。"; return
    fi

    echo "选择摧毁目标:"
    for i in "${!domains[@]}"; do
        echo "$((i+1)). ${domains[$i]}"
    done
    echo "0. 取消"

    read -p "请输入序号: " choice
    if [ "$choice" == "0" ]; then return; fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#domains[@]}" ]; then
        echo -e "${RED}输入无效。${NC}"; return
    fi

    local DEL_DOMAIN="${domains[$((choice-1))]}"
    
    echo -e "${YELLOW}正在执行深度清理: $DEL_DOMAIN ...${NC}"
    rm -f "/etc/nginx/sites-available/$DEL_DOMAIN"
    rm -f "/etc/nginx/sites-enabled/$DEL_DOMAIN"
    rm -rf "$BASE_DIR/$DEL_DOMAIN"
    certbot delete --cert-name "$DEL_DOMAIN" --non-interactive > /dev/null 2>&1
    
    safe_reload
    echo -e "${GREEN}域名 [$DEL_DOMAIN] 已彻底抹除。${NC}"
}

init_env
clear
while true; do
    echo -e "\n=============================================="
    echo -e "         ${GREEN}API 零信任矩阵网关系统${NC}"
    echo -e "=============================================="
    echo "  1. 部署全新网关节点"
    echo "  2. 管理网关内部路由"
    echo "  3. 视察全网透视矩阵"
    echo "  4. 彻底摧毁网关节点"
    echo "  0. 退出管理系统"
    echo "----------------------------------------------"
    read -p "请输入指令: " menu_choice

    case $menu_choice in
        1) deploy_domain ;;
        2) manage_paths ;;
        3) list_status ;;
        4) delete_domain ;;
        0) echo -e "${GREEN}控制权已交还。${NC}\n"; exit 0 ;;
        *) echo -e "${RED}指令无效。${NC}" ;;
    esac
done
