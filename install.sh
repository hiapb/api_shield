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
        ssl_headers="proxy_ssl_server_name on;
    proxy_ssl_name $target_domain;"
    fi

    local clean_target_path="$target_path"
    if [ "$target_path" != "/" ] && [ -n "$target_path" ]; then
        clean_target_path=$(echo "$target_path" | sed 's/\/$//')
    fi
    local clean_api_path=$(echo "$api_path" | sed 's/\/$//')

    # ====================================================
    # 核心组件：AI 流式引擎 (SSE) 与长链接大载荷优化模块
    # ====================================================
    local AI_OPTIMIZE_BLOCK="
    proxy_http_version 1.1;

    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header REMOTE-HOST \$remote_addr;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \"\";
    proxy_set_header Accept-Encoding \"\";

    client_max_body_size 500M;

    proxy_connect_timeout 60s;
    proxy_send_timeout 1800s;
    proxy_read_timeout 1800s;
    send_timeout 1800s;

    proxy_request_buffering off;
    proxy_buffering off;
    proxy_cache off;
    proxy_next_upstream off;

    add_header X-Accel-Buffering no always;
    add_header Cache-Control no-cache always;
    "

    if [ "$clean_api_path" == "" ]; then
        # 根路径全量代理 ( / )
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
    $AI_OPTIMIZE_BLOCK
}
EOF
    elif [ -z "$clean_target_path" ]; then
        # 子路径原样透传 (彻底根除 301 重定向问题)
        cat > "$save_path" <<EOF
# META_TYPE: SUB_ROUTE
# META_DISPLAY: ${clean_api_path} ===> ${target_proto}://${target_domain} (双轨原样透传)
location = ${clean_api_path} {
    proxy_pass ${target_proto}://${target_domain};
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    $AI_OPTIMIZE_BLOCK
}

location ^~ ${clean_api_path}/ {
    proxy_pass ${target_proto}://${target_domain};
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    $AI_OPTIMIZE_BLOCK
}
EOF
    else
        # 子路径重写映射
        local safe_regex_api=$(escape_regex "$clean_api_path")

        cat > "$save_path" <<EOF
# META_TYPE: SUB_ROUTE
# META_DISPLAY: ${clean_api_path} ===> ${target_proto}://${target_domain}${clean_target_path} (双轨重写)
location = ${clean_api_path} {
    proxy_pass ${target_proto}://${target_domain}${clean_target_path};
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    $AI_OPTIMIZE_BLOCK
}

location ^~ ${clean_api_path}/ {
    rewrite ^${safe_regex_api}/(.*)\$ ${clean_target_path}/\$1 break;
    proxy_pass ${target_proto}://${target_domain};
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    $AI_OPTIMIZE_BLOCK
}
EOF
    fi
}

function generate_ai_api_bundle_block() {
    local api_path=$1
    local target_proto=$2
    local target_domain=$3
    local target_path=$4
    local save_path=$5

    local ssl_headers=""
    if [ "$target_proto" == "https" ]; then
        ssl_headers="proxy_ssl_server_name on;
    proxy_ssl_name $target_domain;"
    fi

    local clean_api_path
    clean_api_path=$(echo "$api_path" | sed 's/\/$//')
    if [ -z "$clean_api_path" ]; then
        clean_api_path=""
    fi

    local clean_target_path="$target_path"
    if [ "$clean_target_path" == "/" ]; then
        clean_target_path=""
    elif [ -n "$clean_target_path" ]; then
        clean_target_path=$(echo "$clean_target_path" | sed 's/\/$//')
    fi

    local upstream="${target_proto}://${target_domain}"
    local meta_target="$upstream"
    if [ -n "$clean_target_path" ]; then
        meta_target="${upstream}${clean_target_path}"
    fi

    local meta_mount="/"
    if [ -n "$clean_api_path" ]; then
        meta_mount="$clean_api_path"
    fi

    local common_headers="
    proxy_http_version 1.1;
    proxy_set_header Host $target_domain;
    $ssl_headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header REMOTE-HOST \$remote_addr;
    proxy_set_header Connection \"\";
    proxy_set_header Accept-Encoding \"\";
    "

    local stream_opts="
    client_max_body_size 500M;
    proxy_connect_timeout 120s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;
    send_timeout 3600s;
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    gzip off;
    add_header X-Accel-Buffering no always;
    add_header Cache-Control \"no-cache, no-transform\" always;
    "

    local upload_opts="
    client_max_body_size 800M;
    proxy_connect_timeout 120s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;
    send_timeout 3600s;
    proxy_request_buffering on;
    proxy_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    gzip off;
    add_header Cache-Control \"no-cache, no-transform\" always;
    "

    local normal_opts="
    client_max_body_size 500M;
    proxy_connect_timeout 120s;
    proxy_send_timeout 1800s;
    proxy_read_timeout 1800s;
    send_timeout 1800s;
    proxy_request_buffering on;
    proxy_buffering off;
    proxy_cache off;
    proxy_next_upstream off;
    gzip off;
    add_header Cache-Control \"no-cache, no-transform\" always;
    "

    local safe_regex_api=""
    if [ -n "$clean_api_path" ]; then
        safe_regex_api=$(escape_regex "$clean_api_path")
    fi

    # 生成 location 时：
    # - 对外路径 = 挂载路径 + 标准 API 路径，例如 /cn/v1/responses
    # - 后端路径 = 后端真实映射路径 + 标准 API 路径，例如 /v1/responses 或 /proxy/v1/responses
    local P="$clean_api_path"
    local T="$clean_target_path"

    local rewrite_responses=""
    local rewrite_codex=""
    local rewrite_v1beta=""
    local rewrite_antigravity_v1beta=""
    local rewrite_v1_files=""
    local rewrite_v1_uploads=""
    local rewrite_v1_batches=""
    local rewrite_v1_fine_tuning=""
    local rewrite_v1_fallback=""

    if [ -n "$P" ] || [ -n "$T" ]; then
        rewrite_responses="    rewrite ^${safe_regex_api}/responses/(.*)\$ ${T}/responses/\$1 break;"
        rewrite_codex="    rewrite ^${safe_regex_api}/backend-api/codex/responses/(.*)\$ ${T}/backend-api/codex/responses/\$1 break;"
        rewrite_v1beta="    rewrite ^${safe_regex_api}/v1beta/(.*)\$ ${T}/v1beta/\$1 break;"
        rewrite_antigravity_v1beta="    rewrite ^${safe_regex_api}/antigravity/v1beta/(.*)\$ ${T}/antigravity/v1beta/\$1 break;"
        rewrite_v1_files="    rewrite ^${safe_regex_api}/v1/files(.*)\$ ${T}/v1/files\$1 break;"
        rewrite_v1_uploads="    rewrite ^${safe_regex_api}/v1/uploads(.*)\$ ${T}/v1/uploads\$1 break;"
        rewrite_v1_batches="    rewrite ^${safe_regex_api}/v1/batches(.*)\$ ${T}/v1/batches\$1 break;"
        rewrite_v1_fine_tuning="    rewrite ^${safe_regex_api}/v1/fine_tuning(.*)\$ ${T}/v1/fine_tuning\$1 break;"
        rewrite_v1_fallback="    rewrite ^${safe_regex_api}/v1/(.*)\$ ${T}/v1/\$1 break;"
    fi

    cat > "$save_path" <<EOF
# META_TYPE: AI_BUNDLE
# META_DISPLAY: ${meta_mount} AI API 全家桶 ===> $meta_target

location = ${P}/v1/responses {
    proxy_pass ${upstream}${T}/v1/responses;
    $common_headers
    $stream_opts
}

location = ${P}/responses {
    proxy_pass ${upstream}${T}/responses;
    $common_headers
    $stream_opts
}

location ^~ ${P}/responses/ {
$rewrite_responses
    proxy_pass $upstream;
    $common_headers
    $stream_opts
}

location = ${P}/backend-api/codex/responses {
    proxy_pass ${upstream}${T}/backend-api/codex/responses;
    $common_headers
    $stream_opts
}

location ^~ ${P}/backend-api/codex/responses/ {
$rewrite_codex
    proxy_pass $upstream;
    $common_headers
    $stream_opts
}

location = ${P}/v1/chat/completions {
    proxy_pass ${upstream}${T}/v1/chat/completions;
    $common_headers
    $stream_opts
}

location = ${P}/v1/completions {
    proxy_pass ${upstream}${T}/v1/completions;
    $common_headers
    $stream_opts
}

location = ${P}/v1/messages {
    proxy_pass ${upstream}${T}/v1/messages;
    $common_headers
    $stream_opts
}

location = ${P}/antigravity/v1/messages {
    proxy_pass ${upstream}${T}/antigravity/v1/messages;
    $common_headers
    $stream_opts
}

location ^~ ${P}/v1beta/ {
$rewrite_v1beta
    proxy_pass $upstream;
    $common_headers
    $stream_opts
}

location ^~ ${P}/antigravity/v1beta/ {
$rewrite_antigravity_v1beta
    proxy_pass $upstream;
    $common_headers
    $stream_opts
}

location = ${P}/v1/messages/count_tokens {
    proxy_pass ${upstream}${T}/v1/messages/count_tokens;
    $common_headers
    $normal_opts
}

location = ${P}/v1/messages/batches {
    proxy_pass ${upstream}${T}/v1/messages/batches;
    $common_headers
    $upload_opts
}

location = ${P}/v1/images/generations {
    proxy_pass ${upstream}${T}/v1/images/generations;
    $common_headers
    $upload_opts
}

location = ${P}/v1/images/edits {
    proxy_pass ${upstream}${T}/v1/images/edits;
    $common_headers
    $upload_opts
}

location = ${P}/v1/images/variations {
    proxy_pass ${upstream}${T}/v1/images/variations;
    $common_headers
    $upload_opts
}

location ^~ ${P}/v1/files {
$rewrite_v1_files
    proxy_pass $upstream;
    $common_headers
    $upload_opts
}

location ^~ ${P}/v1/uploads {
$rewrite_v1_uploads
    proxy_pass $upstream;
    $common_headers
    $upload_opts
}

location ^~ ${P}/v1/batches {
$rewrite_v1_batches
    proxy_pass $upstream;
    $common_headers
    $upload_opts
}

location ^~ ${P}/v1/fine_tuning {
$rewrite_v1_fine_tuning
    proxy_pass $upstream;
    $common_headers
    $upload_opts
}

location = ${P}/v1/audio/transcriptions {
    proxy_pass ${upstream}${T}/v1/audio/transcriptions;
    $common_headers
    $upload_opts
}

location = ${P}/v1/audio/translations {
    proxy_pass ${upstream}${T}/v1/audio/translations;
    $common_headers
    $upload_opts
}

location = ${P}/v1/audio/speech {
    proxy_pass ${upstream}${T}/v1/audio/speech;
    $common_headers
    $upload_opts
}

location = ${P}/v1/models {
    proxy_pass ${upstream}${T}/v1/models;
    $common_headers
    $normal_opts
}

location = ${P}/v1/embeddings {
    proxy_pass ${upstream}${T}/v1/embeddings;
    $common_headers
    $normal_opts
}

location = ${P}/v1/moderations {
    proxy_pass ${upstream}${T}/v1/moderations;
    $common_headers
    $normal_opts
}

location ${P}/v1/ {
$rewrite_v1_fallback
    proxy_pass $upstream;
    $common_headers
    $normal_opts
}
EOF
}

function deploy_domain() {
    echo -e "\n${CYAN}--- 部署全新网关节点 ---${NC}"
    
    local MY_DOMAIN TARGET_DOMAIN API_PATH TARGET_PATH DOMAIN_TYPE
    
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
        read -p "请选择 (1/2): " proto_choice
        if [[ "$proto_choice" == "1" || "$proto_choice" == "2" ]]; then break; fi
    done
    TARGET_PROTO=$([ "$proto_choice" == "1" ] && echo "http" || echo "https")
    local ROUTE_PROFILE

    while true; do
        read -p "3. 请输入反代源站 (限 域名/IPv4/localhost[:port]): " TARGET_DOMAIN
        if validate_target "$TARGET_DOMAIN"; then break; fi
        echo -e "${RED}目标格式非法 (暂不支持 IPv6)。${NC}"
    done

    echo -e "4. 请选择路由类型:"
    echo "   [1] 通用反代"
    echo "   [2] AI API 全家桶"
    while true; do
        read -p "   请选择 (1/2): " ROUTE_PROFILE
        if [[ "$ROUTE_PROFILE" == "1" || "$ROUTE_PROFILE" == "2" ]]; then break; fi
    done
    DOMAIN_TYPE=$([ "$ROUTE_PROFILE" == "2" ] && echo "AI_GATEWAY" || echo "COMMON_PROXY")

    while true; do
        if [ "$ROUTE_PROFILE" == "2" ]; then
            read -p "5. 请输入 AI 全家桶对外挂载路径 (输入 / 表示根路径): " API_PATH
        else
            read -p "5. 请输入对外放行路径 (输入 / 为全量穿透): " API_PATH
        fi
        if validate_path "$API_PATH"; then break; fi
        echo -e "${RED}路径非法。${NC}"
    done

    read -p "6. 请输入后端真实映射路径 (直接回车保持原样透传): " TARGET_PATH
    if [ -n "$TARGET_PATH" ] && ! validate_path "$TARGET_PATH"; then
        echo -e "${YELLOW}映射路径非法，已强制降维至 [原样透传] 模式。${NC}"
        TARGET_PATH=""
    fi

    echo -e "7. 是否开启 User-Agent 嗅探拦截?"
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
    echo "$DOMAIN_TYPE" > "$BASE_DIR/$MY_DOMAIN/.domain_type"
    local PATH_CONF
    local SAFE_HASH=$(echo -n "$ROUTE_PROFILE:$API_PATH" | sha256sum | awk '{print $1}' | cut -c 1-8)
    if [ "$ROUTE_PROFILE" == "2" ]; then
        PATH_CONF="$BASE_DIR/$MY_DOMAIN/route_ai_${SAFE_HASH}.conf"
        generate_ai_api_bundle_block "$API_PATH" "$TARGET_PROTO" "$TARGET_DOMAIN" "$TARGET_PATH" "$PATH_CONF"
    else
        PATH_CONF="$BASE_DIR/$MY_DOMAIN/route_${SAFE_HASH}.conf"
        generate_proxy_block "$API_PATH" "$TARGET_PROTO" "$TARGET_DOMAIN" "$TARGET_PATH" "$PATH_CONF"
    fi
    manage_blackhole "$BASE_DIR/$MY_DOMAIN"

    # =========================================================================
    # [核心修复区] 彻底解决证书断期问题，保障 Certbot 后台探针不受代理流量干扰
    # =========================================================================
    cat > "$TMP_CONF" <<EOF
server {
    listen 80;
    server_name $MY_DOMAIN;
    
    # 物理隔离 ACME 探针流量，绝对豁免重定向
    location /.well-known/acme-challenge/ {
        root $ACME_DIR;
    }
    
    # 纯净业务流量执行强制 HTTPS 升维
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $MY_DOMAIN;
    underscores_in_headers on;
    client_max_body_size 800M;
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
    local DOMAIN_TYPE=""
    if [ -f "$DOMAIN_DIR/.domain_type" ]; then
        DOMAIN_TYPE=$(cat "$DOMAIN_DIR/.domain_type" 2>/dev/null | tr -d '[:space:]')
    fi
    # 兼容旧版本：没有 .domain_type 时，根据已有配置自动推断一次
    if [ -z "$DOMAIN_TYPE" ]; then
        if grep -Rqs "# META_TYPE: AI_BUNDLE" "$DOMAIN_DIR"/*.conf 2>/dev/null; then
            DOMAIN_TYPE="AI_GATEWAY"
        else
            DOMAIN_TYPE="COMMON_PROXY"
        fi
        echo "$DOMAIN_TYPE" > "$DOMAIN_DIR/.domain_type"
    fi

    # ================= 交互状态机循环 =================
    while true; do
        echo -e "\n=============================================="
        echo -e "当前操作域: ${GREEN}$SELECT_DOMAIN${NC}"
        if [ "$DOMAIN_TYPE" == "AI_GATEWAY" ]; then
            echo -e "节点类型: ${CYAN}AI API 全家桶${NC}"
        else
            echo -e "节点类型: ${CYAN}通用反代${NC}"
        fi
        echo -e "当前已挂载链路："
        
        shopt -s nullglob
        local conf_list=("$DOMAIN_DIR"/*.conf)
        shopt -u nullglob
        
        local auto_proto=""
        local auto_target=""
        local path_count=0

        for conf in "${conf_list[@]}"; do
            [[ "$(basename "$conf")" == "00_blackhole.conf" ]] && continue
            
            local meta_disp=$(grep "^# META_DISPLAY:" "$conf" | sed 's/^# META_DISPLAY:[[:space:]]*//' 2>/dev/null)
            if [ -n "$meta_disp" ]; then
                echo -e "  ↳ ${YELLOW}$meta_disp${NC}"
                path_count=$((path_count + 1))
            fi
            
            # AST级正则解析：从现有配置中提取上游物理源站记忆
            if [ -z "$auto_target" ]; then
                local p_pass=$(grep -m 1 "proxy_pass" "$conf" | awk '{print $2}' | tr -d ';' 2>/dev/null)
                if [[ "$p_pass" =~ ^(https?)://([^/]+) ]]; then
                    auto_proto="${BASH_REMATCH[1]}"
                    auto_target="${BASH_REMATCH[2]}"
                fi
            fi
        done
        
        if [ $path_count -eq 0 ]; then
             echo -e "  ↳ ${RED}[空矩阵] 警告：暂无任何自定义路由${NC}"
        fi
        echo -e "==============================================\n"

        echo "1. 挂载新路由"
        echo "2. 删除路由"
        echo "0. 返回"
        local op_choice
        read -p "选择操作: " op_choice

        if [ "$op_choice" == "0" ]; then
            break # 打破内层循环，返回主菜单
        elif [ "$op_choice" == "1" ]; then
            local TARGET_PROTO=""
            local TARGET_DOMAIN=""
            local API_PATH TARGET_PATH
            local ROUTE_PROFILE

            if [ -n "$auto_target" ]; then
                echo -e "探测到当前主源站记忆为: ${CYAN}${auto_proto}://${auto_target}${NC}"
                read -p "是否直接沿用该源站？[Y/n] (默认回车沿用): " use_auto
                if [[ ! "$use_auto" =~ ^[Nn]$ ]]; then
                    TARGET_PROTO="$auto_proto"
                    TARGET_DOMAIN="$auto_target"
                fi
            fi

            if [ -z "$TARGET_DOMAIN" ]; then
                echo -e "   [1] HTTP
   [2] HTTPS"
                while true; do
                    read -p "选择协议 (1/2): " proto_choice
                    if [[ "$proto_choice" == "1" || "$proto_choice" == "2" ]]; then break; fi
                done
                TARGET_PROTO=$([ "$proto_choice" == "1" ] && echo "http" || echo "https")
                while true; do read -p "反代源站 (域名/IPv4/localhost[:port]): " TARGET_DOMAIN; if validate_target "$TARGET_DOMAIN"; then break; fi; done
            fi

            while true; do
                if [ "$DOMAIN_TYPE" == "AI_GATEWAY" ]; then
                    read -p "AI 全家桶对外挂载路径 (例如 /openai，输入 / 表示根路径): " API_PATH
                else
                    read -p "对外放行路径 (例如 /api，输入 / 为全量穿透): " API_PATH
                fi
                if validate_path "$API_PATH"; then break; fi
                echo -e "${RED}路径非法。${NC}"
            done
            
            read -p "后端真实映射路径 (直接回车保持透传): " TARGET_PATH
            if [ -n "$TARGET_PATH" ] && ! validate_path "$TARGET_PATH" ]; then TARGET_PATH=""; fi

            local SAFE_HASH=$(echo -n "$DOMAIN_TYPE:$API_PATH" | sha256sum | awk '{print $1}' | cut -c 1-8)
            local PATH_CONF
            if [ "$DOMAIN_TYPE" == "AI_GATEWAY" ]; then
                PATH_CONF="$DOMAIN_DIR/route_ai_${SAFE_HASH}.conf"
            else
                PATH_CONF="$DOMAIN_DIR/route_${SAFE_HASH}.conf"
            fi
            
            if [ -f "$PATH_CONF" ]; then
                echo -e "${RED}该对外挂载路径已存在：$API_PATH${NC}"
                echo -e "${YELLOW}为避免把旧路由覆盖，请先删除原路由，或换一个新路径。${NC}"
                continue
            fi

            if [ "$DOMAIN_TYPE" == "AI_GATEWAY" ]; then
                generate_ai_api_bundle_block "$API_PATH" "$TARGET_PROTO" "$TARGET_DOMAIN" "$TARGET_PATH" "$PATH_CONF"
            else
                generate_proxy_block "$API_PATH" "$TARGET_PROTO" "$TARGET_DOMAIN" "$TARGET_PATH" "$PATH_CONF"
            fi
            manage_blackhole "$DOMAIN_DIR"

            if safe_reload; then
                echo -e "${GREEN}路由链路贯通成功。${NC}"
            else
                echo -e "${RED}路由注入失败，已回滚本次新增。${NC}"
                rm -f "$PATH_CONF"
                manage_blackhole "$DOMAIN_DIR"
                safe_reload 
            fi

        elif [ "$op_choice" == "2" ]; then
            local path_files=()
            for f in "${conf_list[@]}"; do
                [[ "$(basename "$f")" != "00_blackhole.conf" ]] && [ -f "$f" ] && path_files+=("$f")
            done

            if [ ${#path_files[@]} -eq 0 ]; then 
                echo -e "${YELLOW}暂无自定义路由可供抹除。${NC}"
                continue
            fi

            echo -e "\n选择需要删除的路由:"
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
            if ! validate_number "$p_choice" || (( p_choice < 0 || p_choice > ${#path_files[@]} )); then continue; fi
            if [ "$p_choice" == "0" ]; then continue; fi

            local DEL_FILE="${path_files[$((p_choice-1))]}"
            
            cp "$DEL_FILE" "${DEL_FILE}.bak"
            CLEANUP_FILES+=("${DEL_FILE}.bak")
            rm -f "$DEL_FILE"
            
            # 核心机制：自愈降级链路检测
            # 若删除后矩阵为空，且系统留有主源站记忆，则自动回落到全网放行 /
            if [ $((${#path_files[@]} - 1)) -eq 0 ] && [ -n "$auto_target" ]; then
                echo -e "\n${YELLOW}=== 触发降级保护机制 ===${NC}"
                echo -e "系统检测到路由矩阵已被清空。为了保障业务连续性，已自动接管全量流量 (/) 并直通主源站：${auto_target}"
                
                local SAFE_HASH=$(echo -n "/" | sha256sum | awk '{print $1}' | cut -c 1-8)
                local FALLBACK_CONF="$DOMAIN_DIR/route_${SAFE_HASH}.conf"
                
                generate_proxy_block "/" "$auto_proto" "$auto_target" "" "$FALLBACK_CONF"
            fi
            
            manage_blackhole "$DOMAIN_DIR"
            
            if safe_reload; then
                rm -f "${DEL_FILE}.bak"
                echo -e "${GREEN}操作执行完毕，路由体系已刷新。${NC}"
            else
                echo -e "${RED}引擎重载受阻，启动恢复程序...${NC}"
                mv "${DEL_FILE}.bak" "$DEL_FILE"
                
                # 如果降级失败，清扫自动生成的 fallback 文件
                if [ $((${#path_files[@]} - 1)) -eq 0 ] && [ -n "$auto_target" ]; then
                    rm -f "$DOMAIN_DIR/route_$(echo -n "/" | sha256sum | awk '{print $1}' | cut -c 1-8).conf"
                fi
                
                manage_blackhole "$DOMAIN_DIR"
                safe_reload
            fi
        fi
    done
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
            ((++count))
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


function uninstall_system() {
    echo -e "\n${RED}================ [ 毁灭级操作警告 ] =================${NC}"
    echo -e "${YELLOW}您正在触发网关矩阵的自毁程序。此操作将执行物理扇区级的彻底净化，包含：${NC}"
    echo -e "  1. 暴力阻断并卸载 Nginx 与 Certbot 核心引擎"
    echo -e "  2. ${RED}无差别抹除${NC} /etc/nginx 所有配置 (包含非本系统创建的其他站点！)"
    echo -e "  3. 吊销并焚毁 /etc/letsencrypt 下的所有 TLS 证书资产"
    echo -e "  4. 销毁网关矩阵隔离目录 ($BASE_DIR) 及 ACME 验证目录"
    echo -e "\n${RED}极度危险：如果此台物理机/VPS 上还有其他依赖 Nginx 的业务，它们将随之瞬间蒸发！${NC}"
    
    local confirm_destroy
    read -p "若已评估所有损失并决意销毁，请输入大写 'DESTROY' 确认执行: " confirm_destroy
    
    if [ "$confirm_destroy" != "DESTROY" ]; then
        echo -e "\n${GREEN}[系统哨兵] 校验密令不匹配，自毁程序已中止，系统安然无恙。${NC}"
        return
    fi

    echo -e "\n${CYAN}>>> 开始执行降维打击，剥离核心服务...${NC}"
    systemctl stop nginx >/dev/null 2>&1
    systemctl disable nginx >/dev/null 2>&1

    echo -e "${CYAN}>>> 正在拆除底层依赖组件 (Nginx & Certbot)...${NC}"
    
    export DEBIAN_FRONTEND=noninteractive
    
    # 引入强制参数，确保包管理器不再询问关于配置文件的操作
    apt-get purge -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" nginx nginx-common nginx-core certbot >/dev/null 2>&1
    apt-get autoremove -y >/dev/null 2>&1
    
    # 撤销环境变量，保持系统终端后续整洁
    unset DEBIAN_FRONTEND

    echo -e "${CYAN}>>> 正在执行深度目录焚毁，不留任何死角...${NC}"
    rm -rf /etc/nginx
    rm -rf /etc/letsencrypt
    rm -rf /var/lib/letsencrypt
    rm -rf /var/log/letsencrypt
    rm -rf "$ACME_DIR"
    rm -rf "$BASE_DIR"

    echo -e "${GREEN}净化完成。API 零信任矩阵网关已从当前物理空间彻底抹除。${NC}"
    echo -e "控制权已交还，系统将在此次会话后退出。"
    exit 0
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
    echo "  5. 毁灭级系统全量卸载"
    echo "  0. 安全退出"
    echo "----------------------------------------------"
    read -p "请输入指令: " menu_choice

    case $menu_choice in
        1) deploy_domain ;;
        2) manage_paths ;;
        3) list_status ;;
        4) delete_domain ;;
        5) uninstall_system ;;
        0) echo -e "${GREEN}控制权已交还。${NC}\n"; exit 0 ;;
        *) echo -e "${RED}非法指令。${NC}" ;;
    esac
done
