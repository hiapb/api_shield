#!/bin/bash

# ====================================================
# 项目：API 零信任流量护城河 (API Zero-Trust Shield)
# 描述：专为高价值流量节点打造的防扫描、防盗刷反代网关
# 环境：Debian / Ubuntu
# ====================================================

# 终端色彩定义
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 权限与系统架构预检
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}严重错误：底层网络与证书配置需要最高权限。请使用 root 账号或 sudo 执行本脚本。${NC}"
  exit 1
fi

if [ ! -f /etc/debian_version ]; then
    echo -e "${RED}兼容性中断：本护城河系统目前仅支持 Debian 或 Ubuntu 操作系统。${NC}"
    exit 1
fi

# 环境初始化与依赖灌入
function init_env() {
    if ! command -v nginx >/dev/null 2>&1 || ! command -v certbot >/dev/null 2>&1; then
        echo -e "${CYAN}正在为您构筑底层依赖环境 (Nginx & Certbot)...${NC}"
        apt-get update -qq
        apt-get install -y nginx certbot python3-certbot-nginx > /dev/null 2>&1
        rm -f /etc/nginx/sites-enabled/default
        systemctl enable nginx
        systemctl start nginx
    fi
}

# 模块一：部署反代节点 (严格校验输入)
function add_proxy() {
    echo -e "\n${CYAN}>>> 部署全新的反代节点 <<<${NC}"
    
    # 强制输入自有域名
    while true; do
        read -p "步骤 1: 请输入您的自有域名 (例如 api.yourdomain.com): " MY_DOMAIN
        MY_DOMAIN=$(echo "$MY_DOMAIN" | tr -d ' ')
        if [ -n "$MY_DOMAIN" ]; then break; fi
        echo -e "${RED}输入阻断：域名为底层寻址基础，不可为空，请重新输入。${NC}"
    done

    # 强制输入目标源站
    while true; do
        read -p "步骤 2: 请输入需反代的目标源站 (例如 codex.mist.pw): " TARGET_DOMAIN
        TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | tr -d ' ')
        if [ -n "$TARGET_DOMAIN" ]; then break; fi
        echo -e "${RED}输入阻断：目标源站为核心路由节点，不可为空，请重新输入。${NC}"
    done

    # 强制输入放行路径
    while true; do
        read -p "步骤 3: 请输入唯一的 API 放行路径 (例如 /responses 或 /v1/): " API_PATH
        API_PATH=$(echo "$API_PATH" | tr -d ' ')
        if [ -n "$API_PATH" ]; then break; fi
        echo -e "${RED}输入阻断：为保证零信任安全机制，必须显式指定一个业务放行路径。${NC}"
    done

    echo -e "${YELLOW}参数捕获完毕。正在建立安全隧道并申请 SSL 证书，请稍候...${NC}"
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
        echo -e "${RED}部署失败：证书机构拒绝签发。${NC}"
        echo -e "排查指南：请务必确保您的域名已在 DNS 服务商处，正确添加 A 记录并指向了本台服务器的公网 IP。"
        rm -f "$TMP_CONF" /etc/nginx/sites-enabled/"$MY_DOMAIN"
        systemctl reload nginx
        return
    fi

    echo -e "${CYAN}证书签发完毕，正在注入高频防御规则...${NC}"
    cat > "$TMP_CONF" <<EOF
server {
    listen 80;
    server_name $MY_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $MY_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$MY_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$MY_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # 封锁特征扫描器与爬虫
    if (\$http_user_agent ~* (curl|wget|python|java|go-http-client|nikto|nmap|zgrab|masscan)) {
        return 444; 
    }

    # 阻断所有非授权的路径嗅探，保护流量余额
    location / {
        return 444;
    }

    # 业务放行：仅允许指定路径穿透
    location ^~ $API_PATH {
        proxy_pass https://$TARGET_DOMAIN;
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
}
EOF

    nginx -t > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo -e "${GREEN}恭喜，节点 [$MY_DOMAIN] 部署成功！${NC}"
        echo -e "外界只能通过严格匹配 ${YELLOW}https://$MY_DOMAIN$API_PATH${NC} 进行访问，其他试探将一律被静默抛弃。"
    else
        echo -e "${RED}底层引擎重构异常，为保证服务器稳定，已自动回滚操作。${NC}"
        rm -f "$TMP_CONF" /etc/nginx/sites-enabled/"$MY_DOMAIN"
        systemctl reload nginx
    fi
}

# 模块二：查看运行节点
function list_proxies() {
    echo -e "\n${CYAN}>>> 当前处于保护中的节点 <<<${NC}"
    local count=0
    for conf in /etc/nginx/sites-enabled/*; do
        if [ -f "$conf" ] && [[ "$(basename "$conf")" != "default" ]]; then
            domain=$(basename "$conf")
            path=$(grep -m 1 "location \^~" "$conf" | awk '{print $3}')
            target=$(grep -m 1 "proxy_pass" "$conf" | awk '{print $2}' | tr -d ';')
            echo -e "盾牌开启: ${GREEN}$domain${NC} | 开放暗门: ${GREEN}${path:-解析失败}${NC} | 保护源站: ${GREEN}${target:-解析失败}${NC}"
            ((count++))
        fi
    done
    if [ "$count" -eq 0 ]; then echo "当前尚未部署任何保护节点。"; fi
}

# 模块三：销毁指定节点
function delete_proxy() {
    echo -e "\n${CYAN}>>> 销毁指定节点 <<<${NC}"
    local domains=()
    for conf in /etc/nginx/sites-enabled/*; do
        if [ -f "$conf" ] && [[ "$(basename "$conf")" != "default" ]]; then
            domains+=("$(basename "$conf")")
        fi
    done

    if [ ${#domains[@]} -eq 0 ]; then
        echo "暂无可以销毁的节点。"
        return
    fi

    # 动态渲染序号菜单
    for i in "${!domains[@]}"; do
        echo "$((i+1)). ${domains[$i]}"
    done
    echo "0. 取消操作并返回主页面"

    read -p "请选择需要彻底抹除的节点序号 [0-$(( ${#domains[@]} ))]: " choice
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#domains[@]}" ]; then
        echo -e "${RED}指令不合法，已终止操作。${NC}"
        return
    fi

    if [ "$choice" -eq 0 ]; then return; fi

    local DEL_DOMAIN="${domains[$((choice-1))]}"
    
    echo -e "${YELLOW}正在执行深度清理，擦除路由配置与加密证书: $DEL_DOMAIN ...${NC}"
    rm -f "/etc/nginx/sites-available/$DEL_DOMAIN"
    rm -f "/etc/nginx/sites-enabled/$DEL_DOMAIN"
    certbot delete --cert-name "$DEL_DOMAIN" --non-interactive > /dev/null 2>&1
    systemctl reload nginx
    
    echo -e "${GREEN}节点 [$DEL_DOMAIN] 的所有痕迹已被物理抹除。${NC}"
}

# 模块四：重载网关引擎
function reload_nginx() {
    echo -e "\n${CYAN}>>> 重载网关引擎 <<<${NC}"
    nginx -t > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo -e "${GREEN}底层网络引擎已完成热重载。${NC}"
    else
        echo -e "${RED}发现致命语法错误，引擎拒绝重载以保护现有连接。请检查 Nginx 配置文件。${NC}"
    fi
}

# 启动与主事件循环
init_env
clear
while true; do
    echo -e "\n=============================================="
    echo -e "          ${GREEN}API 零信任流量护城河 v1.0${NC}"
    echo -e "=============================================="
    echo "  1. 部署反代节点"
    echo "  2. 查看运行节点"
    echo "  3. 销毁指定节点"
    echo "  4. 重载网关引擎"
    echo "  0. 退出管理系统"
    echo "----------------------------------------------"
    read -p "老板，请下达执行指令 [0-4]: " menu_choice

    case $menu_choice in
        1) add_proxy ;;
        2) list_proxies ;;
        3) delete_proxy ;;
        4) reload_nginx ;;
        0) echo -e "${GREEN}系统已挂起。${NC}\n"; exit 0 ;;
        *) echo -e "${RED}无法识别该指令，请重新输入。${NC}" ;;
    esac
done
