# dnsmgr-ddns
基于彩虹聚合DNS的DDNS脚本

建议开一个子用户给单独的域名权限来DDNS

放在/root/dnsmgr-ddns.sh

赋予脚本权限：`chmod +x /root/dnsmgr-ddns.sh`

需要jq：`apt install jq -y`

`bash dnsmgr-ddns.sh`测试运行

添加定时任务：`crontab -e`

`*/5 * * * * /root/dnsmgr-ddns.sh >> /var/log/dnsmgr-ddns.log 2>&1`

以下是脚本
```
#!/usr/bin/env bash
# 测试可用于彩虹聚合dns V2.11 (Build 1042) AI生成

set -euo pipefail

# 需修改的配置
API_BASE="https://dns.example.com"  # API地址（末尾不要斜杠）
USER_ID="用户ID"
API_KEY="API密钥"
DDNS_FQDN="ddns.example.com"         # 要DDNS的域名
TTL=600                             # TTL（会自动不低于平台最小TTL）
LINE_ID="default"                   # 线路ID

# 日志相关（同目录自动生成配置文件，可在配置里改）
DEFAULT_LOG_MAX_LINES=1000

########################################
# 内部变量（无需修改）
########################################
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${DIR}/dnsmgr-ddns.log"
CONF_FILE="${DIR}/dnsmgr-ddns.log.conf"
LOCK_DIR="${DIR}/.dnsmgr-ddns.lock"

# 运行锁，防并发
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  echo "Another instance is running. Exit." >&2
  exit 0
fi
cleanup() { rmdir "${LOCK_DIR}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# 生成/加载日志配置
if [[ ! -f "${CONF_FILE}" ]]; then
  {
    echo "# Auto-generated log config for dnsmgr-ddns.sh"
    echo "LOG_MAX_LINES=${DEFAULT_LOG_MAX_LINES}"
  } > "${CONF_FILE}"
fi
# shellcheck disable=SC1090
source "${CONF_FILE}"
: "${LOG_MAX_LINES:=${DEFAULT_LOG_MAX_LINES}}"

log() {
  local ts; ts="$(date '+%F %T')"
  printf '[%s] %s\n' "${ts}" "$*" >> "${LOG_FILE}"
  # 控制日志行数
  local lines
  lines=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
  if [[ "${lines}" -gt "${LOG_MAX_LINES}" ]]; then
    tail -n "${LOG_MAX_LINES}" "${LOG_FILE}" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "${LOG_FILE}"
  fi
}

# 依赖检测（仅用 jq 解析 JSON；另需 curl 与 md5sum）
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need_cmd curl
need_cmd jq
need_cmd md5sum

# 签名：md5(user_id+timestamp+key) 小写
make_sign() {
  local ts s raw
  ts="$(date +%s)"
  s="${USER_ID}${ts}${API_KEY}"
  raw="$(printf '%s' "${s}" | md5sum)"; raw="${raw%% *}"
  printf '%s|%s' "${ts}" "${raw}"
}

api_post() {
  # 用法：api_post "/path" "k=v" "k=v" ...
  local path="$1"; shift
  local ts sign
  IFS="|" read -r ts sign < <(make_sign)
  local url="${API_BASE}${path}"
  local args=( -sS -X POST "${url}"
               --data-urlencode "uid=${USER_ID}"
               --data-urlencode "timestamp=${ts}"
               --data-urlencode "sign=${sign}" )
  for kv in "$@"; do
    args+=( --data-urlencode "${kv}" )
  done
  curl "${args[@]}"
}

# 获取公网IP
get_ipv4() { curl -4 -fsS ip.sb 2>/dev/null || true; }
get_ipv6() { curl -6 -fsS ip.sb 2>/dev/null || true; }

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ "$1" == *:* ]]; }

# -------- FQDN 规范化：去尾部点、小写、去首尾空白 --------
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }
SANITIZED_FQDN="$(trim "${DDNS_FQDN}")"
SANITIZED_FQDN="${SANITIZED_FQDN%.}"   # 去掉尾部点
SANITIZED_FQDN="${SANITIZED_FQDN,,}"   # 小写

# 在域名列表里找与 FQDN 匹配的主域（最长后缀匹配）
# 仅用 jq 将 rows 输出为 "id<TAB>name"；Bash 里做后缀匹配，避免依赖 jq 的 test/endswith 等函数
find_domain() {
  local fqdn="$1" resp
  resp="$(api_post "/api/domain" "offset=0" "limit=100")" || true

  # 安全地取出 id 和 name；如果 rows 缺失或不是数组，得到空输出
  local lines
  lines="$(jq -r '
    if (type=="object" and has("rows") and (.rows|type)=="array") then
      .rows[] | "\(.id)\t\(.name)"
    else
      empty
    end
  ' <<< "${resp}" 2>/dev/null || true)"

  if [[ -z "${lines}" ]]; then
    log "find_domain(): unexpected response (no rows parsed): ${resp}; fqdn=${fqdn}"
    printf '%s' ""
    return 0
  fi

  local best_id="" best_name="" best_len=0
  local id name lc_name
  while IFS=$'\t' read -r id name; do
    [[ -z "$id" || -z "$name" ]] && continue
    # 规范化 name：小写、去尾点、去首尾空白
    lc_name="$(trim "${name}")"
    lc_name="${lc_name%.}"
    lc_name="${lc_name,,}"

    # 精确匹配或后缀匹配（fqdn == name 或 fqdn 以 ".name" 结尾）
    if [[ "${fqdn}" == "${lc_name}" || "${fqdn}" == *".${lc_name}" ]]; then
      local nlen=${#lc_name}
      if (( nlen > best_len )); then
        best_len=$nlen
        best_id="$id"
        best_name="$lc_name"
      fi
    fi
  done <<< "${lines}"

  if [[ -n "${best_id}" ]]; then
    printf '{"id":%s,"name":"%s"}' "${best_id}" "${best_name}"
  else
    log "find_domain(): no suffix match; fqdn=${fqdn}; rows=${lines//$'\n'/, }"
    printf '%s' ""
  fi
}

# 查询域名详情，拿 minTTL
get_domain_min_ttl() {
  local domain_id="$1" resp
  resp="$(api_post "/api/domain/${domain_id}" "loginurl=0")" || true
  jq -r 'try .data.minTTL catch empty' <<< "${resp}"
}

# 查询已有记录（按子域 + 类型过滤）
get_record() {
  local domain_id="$1" sub="$2" rtype="$3" resp
  resp="$(api_post "/api/record/data/${domain_id}" "limit=100" "subdomain=${sub}" "type=${rtype}")" || true
  jq -c --arg t "$rtype" '
    try ( ( .rows // [] ) | map(select(.Type==$t)) | ( .[0] // empty ) ) catch empty
  ' <<< "${resp}"
}

# 新增记录
add_record() {
  local domain_id="$1" sub="$2" rtype="$3" value="$4" line="$5" ttl="$6"
  api_post "/api/record/add/${domain_id}" \
    "name=${sub}" "type=${rtype}" "value=${value}" "line=${line}" "ttl=${ttl}"
}

# 修改记录
update_record() {
  local domain_id="$1" rid="$2" sub="$3" rtype="$4" value="$5" line="$6" ttl="$7"
  api_post "/api/record/update/${domain_id}" \
    "recordid=${rid}" "name=${sub}" "type=${rtype}" "value=${value}" "line=${line}" "ttl=${ttl}"
}

########################################
# 主流程
########################################
log "===== dnsmgr-ddns start for ${SANITIZED_FQDN} ====="
log "Using FQDN(normalized)=${SANITIZED_FQDN}"

# 1) 确定主域 & 子域
domain_json="$(find_domain "${SANITIZED_FQDN}")"
if [[ -z "${domain_json}" || "${domain_json}" == "null" ]]; then
  log "ERROR: Unable to find managed domain for ${SANITIZED_FQDN}"
  echo "未在可管理域名中找到 ${SANITIZED_FQDN} 对应主域，退出（详见日志）。" >&2
  exit 1
fi

DOMAIN_ID="$(jq -r '.id'   <<< "${domain_json}")"
DOMAIN_NAME="$(jq -r '.name' <<< "${domain_json}")"

if [[ -z "${DOMAIN_ID}" || -z "${DOMAIN_NAME}" || "${DOMAIN_NAME}" == "null" ]]; then
  log "ERROR: domain_json parse failed: ${domain_json}"
  echo "主域解析失败（详见日志）。" >&2
  exit 1
fi

if [[ "${SANITIZED_FQDN}" == "${DOMAIN_NAME}" ]]; then
  SUBDOMAIN="@"
else
  SUBDOMAIN="${SANITIZED_FQDN%."${DOMAIN_NAME}"}"
fi
log "Resolved domain: id=${DOMAIN_ID}, name=${DOMAIN_NAME}, sub=${SUBDOMAIN}"

# 2) 确保 TTL 不低于平台最小值
min_ttl_str="$(get_domain_min_ttl "${DOMAIN_ID}")" || true
if [[ -n "${min_ttl_str}" && "${min_ttl_str}" =~ ^[0-9]+$ ]]; then
  if (( TTL < min_ttl_str )); then
    log "Adjust TTL from ${TTL} to minTTL ${min_ttl_str}"
    TTL="${min_ttl_str}"
  fi
fi

# 3) 获取公网 IP
IPV4="$(get_ipv4)"; IPV6="$(get_ipv6)"
if is_ipv4 "${IPV4}"; then log "Detected IPv4: ${IPV4}"; else IPV4=""; log "IPv4 not detected"; fi
if is_ipv6 "${IPV6}"; then log "Detected IPv6: ${IPV6}"; else IPV6=""; log "IPv6 not detected"; fi

# 4) 处理 A/AAAA
do_one_type() {
  local rtype="$1" ip="$2"
  if [[ -z "${ip}" ]]; then
    log "Skip ${rtype}: empty IP"
    return 0
  fi

  local rec_json rid cur_val resp code msg
  rec_json="$(get_record "${DOMAIN_ID}" "${SUBDOMAIN}" "${rtype}")"
  if [[ -n "${rec_json}" && "${rec_json}" != "null" ]]; then
    rid="$(jq -r 'try .RecordId catch empty' <<< "${rec_json}")"
    cur_val="$(jq -r 'try .Value    catch empty' <<< "${rec_json}")"
    if [[ -n "${rid}" && -n "${cur_val}" ]]; then
      if [[ "${cur_val}" == "${ip}" ]]; then
        log "No change for ${rtype} ${SANITIZED_FQDN}=${ip}"
      else
        log "Update ${rtype} ${SANITIZED_FQDN}: ${cur_val} -> ${ip}"
        resp="$(update_record "${DOMAIN_ID}" "${rid}" "${SUBDOMAIN}" "${rtype}" "${ip}" "${LINE_ID}" "${TTL}")"
        code="$(jq -r 'try .code catch 0' <<< "${resp}")"
        msg="$(jq -r 'try .msg  catch empty' <<< "${resp}")"
        if [[ "${code}" = "0" ]]; then
          log "Update OK (${rtype})"
        else
          log "Update FAIL (${rtype}): code=${code} msg=${msg} resp=${resp}"
          echo "更新 ${rtype} 记录失败：${msg:-unknown}" >&2
          return 1
        fi
      fi
    else
      # 解析异常：当作不存在处理
      log "Record parse anomaly for ${rtype}; will add"
      resp="$(add_record "${DOMAIN_ID}" "${SUBDOMAIN}" "${rtype}" "${ip}" "${LINE_ID}" "${TTL}")"
      code="$(jq -r 'try .code catch 0' <<< "${resp}")"
      msg="$(jq -r 'try .msg  catch empty' <<< "${resp}")"
      if [[ "${code}" = "0" ]]; then
        log "Add OK (${rtype})"
      else
        log "Add FAIL (${rtype}): code=${code} msg=${msg} resp=${resp}"
        echo "新增 ${rtype} 记录失败：${msg:-unknown}" >&2
        return 1
      fi
    fi
  else
    # 记录不存在，新增
    log "Add ${rtype} ${SANITIZED_FQDN}=${ip}"
    resp="$(add_record "${DOMAIN_ID}" "${SUBDOMAIN}" "${rtype}" "${ip}" "${LINE_ID}" "${TTL}")"
    code="$(jq -r 'try .code catch 0' <<< "${resp}")"
    msg="$(jq -r 'try .msg  catch empty' <<< "${resp}")"
    if [[ "${code}" = "0" ]]; then
      log "Add OK (${rtype})"
    else
      log "Add FAIL (${rtype}): code=${code} msg=${msg} resp=${resp}"
      echo "新增 ${rtype} 记录失败：${msg:-unknown}" >&2
      return 1
    fi
  fi
}

# 分别处理 A/AAAA
do_one_type "A" "${IPV4}" || true
do_one_type "AAAA" "${IPV6}" || true

log "===== dnsmgr-ddns done for ${SANITIZED_FQDN} ====="
echo "DDNS 更新完成（详见 ${LOG_FILE}）。"
```

