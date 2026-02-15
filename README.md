# dnsmgr-ddns
基于彩虹聚合DNS的DDNS脚本

建议开一个子用户给单独的域名权限来DDNS

放在/root/dnsmgr-ddns.sh

赋予脚本权限：`chmod +x /root/dnsmgr-ddns.sh`

需要jq：`apt install jq -y`

`bash dnsmgr-ddns.sh`测试运行

添加定时任务：`crontab -e`

`*/5 * * * * /root/dnsmgr-ddns.sh >/dev/null 2>&1`

会在同目录记录日志

以下是脚本
```
#!/usr/bin/env bash
set -euo pipefail

########################################
# 需修改的配置
########################################
API_BASE="https://dns.example.com"   # API地址（末尾不要斜杠）
USER_ID="用户ID"                     # 必填：用于请求参数 uid
API_KEY="API密钥"                    # 必填：用于签名 sign
DDNS_FQDN="ddns.example.com"         # 要DDNS的域名
LINE_ID="default"               # 线路ID/线路名称（如果不知道是什么可以先在彩虹上添加解析，然后看本站日志 线路 是什么）
TTL=600                              # TTL（会自动不低于平台最小TTL）

ENABLE_IPV4=true                     # true/false：是否更新 A
ENABLE_IPV6=true                     # true/false：是否更新 AAAA

LOG_MAX_LINES=1000                   # 日志最多保留行数（不生成 conf 文件）
LOG_FILE="./dnsmgr-ddns.log"         # 日志文件（相对脚本执行目录）

########################################
# 依赖检测
########################################
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "缺少依赖：$1" >&2; exit 1; }; }
need_cmd curl
need_cmd jq
need_cmd md5sum

########################################
# 日志
########################################
log() {
  local ts; ts="$(date '+%F %T')"
  printf '[%s] %s\n' "${ts}" "$*" >> "${LOG_FILE}"

  local lines
  lines=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)
  if [[ "${lines}" -gt "${LOG_MAX_LINES}" ]]; then
    tail -n "${LOG_MAX_LINES}" "${LOG_FILE}" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "${LOG_FILE}"
  fi
}

########################################
# 基础工具
########################################
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# 归一化IP：处理 ["ip"] / 引号 / IPv6大小写
normalize_ip() {
  local s
  s="$(trim "$1")"

  # JSON 数组形态：["ip"] 或 ["ip","ip2"]，取第一个
  if [[ "$s" == \[*\] ]]; then
    s="$(jq -r 'try .[0] catch empty' <<<"$s" 2>/dev/null || true)"
    s="$(trim "$s")"
  fi

  # 去掉可能的双引号
  s="${s%\"}"; s="${s#\"}"

  # IPv6 统一小写（IPv4 不受影响）
  s="${s,,}"

  printf '%s' "$s"
}

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ "$1" == *:* ]]; }

########################################
# 鉴权 / API
########################################
# sign = md5(uid + timestamp + key) 小写
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

  local kv
  for kv in "$@"; do
    args+=( --data-urlencode "${kv}" )
  done

  curl "${args[@]}"
}

########################################
# 获取公网IP
########################################
get_ipv4() { curl -4 -fsS ip.sb 2>/dev/null || true; }
get_ipv6() { curl -6 -fsS ip.sb 2>/dev/null || true; }

########################################
# 域名/记录相关
########################################
SANITIZED_FQDN="$(trim "${DDNS_FQDN}")"
SANITIZED_FQDN="${SANITIZED_FQDN%.}"
SANITIZED_FQDN="${SANITIZED_FQDN,,}"

# 在域名列表里找与 FQDN 匹配的主域（最长后缀匹配）
find_domain() {
  local fqdn="$1" resp
  resp="$(api_post "/api/domain" "offset=0" "limit=100")" || true

  local lines
  lines="$(jq -r '
    if (type=="object" and has("rows") and (.rows|type)=="array") then
      .rows[] | "\(.id)\t\(.name)"
    else empty end
  ' <<< "${resp}" 2>/dev/null || true)"

  if [[ -z "${lines}" ]]; then
    log "find_domain(): 接口响应异常（未解析到 rows）：${resp}; fqdn=${fqdn}"
    printf '%s' ""
    return 0
  fi

  local best_id="" best_name="" best_len=0
  local id name lc_name
  while IFS=$'\t' read -r id name; do
    [[ -z "$id" || -z "$name" ]] && continue
    lc_name="$(trim "${name}")"
    lc_name="${lc_name%.}"
    lc_name="${lc_name,,}"

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
    log "find_domain(): 未找到后缀匹配；fqdn=${fqdn}; rows=${lines//$'\n'/, }"
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
# 兼容不同返回结构/字段名
get_record() {
  local domain_id="$1" sub="$2" rtype="$3" resp
  resp="$(api_post "/api/record/data/${domain_id}" "limit=100" "subdomain=${sub}" "type=${rtype}")" || true

  jq -c --arg t "$rtype" '
    def pick_type:  (.Type // .type // "");
    def pick_value: (.Value // .value // .content // .Content // "");
    def pick_id:    (.RecordId // .recordid // .id // .Id // "");

    try (
      ( .rows // .data.rows // .Data.rows // [] )
      | map(select((pick_type|tostring) == $t))
      | (.[0] // empty)
      | {
          RecordId: (pick_id|tostring),
          Value: (pick_value|tostring)
        }
    ) catch empty
  ' <<< "${resp}"
}

add_record() {
  local domain_id="$1" sub="$2" rtype="$3" value="$4" line="$5" ttl="$6"
  api_post "/api/record/add/${domain_id}" \
    "name=${sub}" "type=${rtype}" "value=${value}" "line=${line}" "ttl=${ttl}"
}

update_record() {
  local domain_id="$1" rid="$2" sub="$3" rtype="$4" value="$5" line="$6" ttl="$7"
  api_post "/api/record/update/${domain_id}" \
    "recordid=${rid}" "name=${sub}" "type=${rtype}" "value=${value}" "line=${line}" "ttl=${ttl}"
}

########################################
# 核心逻辑：只在变化时更新，并打印归一化前/后
########################################
do_one_type() {
  local rtype="$1" ip="$2" domain_id="$3" sub="$4"

  if [[ -z "${ip}" ]]; then
    log "跳过 ${rtype}：IP 为空"
    return 0
  fi

  local ip_raw ip_norm
  ip_raw="$(trim "${ip}")"
  ip_norm="$(normalize_ip "${ip_raw}")"

  local rec_json rid cur_raw cur_norm resp code msg
  rec_json="$(get_record "${domain_id}" "${sub}" "${rtype}")"

  if [[ -n "${rec_json}" && "${rec_json}" != "null" ]]; then
    rid="$(jq -r 'try .RecordId catch empty' <<< "${rec_json}")"
    rid="$(trim "${rid}")"

    cur_raw="$(jq -r 'try .Value catch empty' <<< "${rec_json}")"
    cur_raw="$(trim "${cur_raw}")"
    cur_norm="$(normalize_ip "${cur_raw}")"

    # 日志：归一化前/后
    log "${rtype} 当前记录(原始)=${cur_raw}"
    log "${rtype} 当前记录(归一化)=${cur_norm}"
    log "${rtype} 本机IP(原始)=${ip_raw}"
    log "${rtype} 本机IP(归一化)=${ip_norm}"

    if [[ -n "${rid}" && -n "${cur_raw}" ]]; then
      if [[ "${cur_norm}" == "${ip_norm}" ]]; then
        log "记录未变化（${rtype} ${SANITIZED_FQDN}=${ip_norm}），不执行更新"
        return 0
      fi

      log "更新 ${rtype} ${SANITIZED_FQDN}：${cur_norm} -> ${ip_norm}"
      resp="$(update_record "${domain_id}" "${rid}" "${sub}" "${rtype}" "${ip_norm}" "${LINE_ID}" "${TTL}")"
      code="$(jq -r 'try .code catch 0' <<< "${resp}")"
      msg="$(jq -r 'try .msg  catch empty' <<< "${resp}")"
      if [[ "${code}" = "0" ]]; then
        log "更新成功（${rtype}）"
      else
        log "更新失败（${rtype}）：code=${code} msg=${msg} resp=${resp}"
        echo "更新 ${rtype} 记录失败：${msg:-unknown}" >&2
        return 1
      fi
    else
      # 解析异常：当作不存在处理 -> 新增
      log "记录解析异常（${rtype}）：rec_json=${rec_json}，尝试新增"
      resp="$(add_record "${domain_id}" "${sub}" "${rtype}" "${ip_norm}" "${LINE_ID}" "${TTL}")"
      code="$(jq -r 'try .code catch 0' <<< "${resp}")"
      msg="$(jq -r 'try .msg  catch empty' <<< "${resp}")"
      if [[ "${code}" = "0" ]]; then
        log "新增成功（${rtype}）"
      else
        log "新增失败（${rtype}）：code=${code} msg=${msg} resp=${resp}"
        echo "新增 ${rtype} 记录失败：${msg:-unknown}" >&2
        return 1
      fi
    fi
  else
    # 记录不存在 -> 新增
    log "新增 ${rtype} ${SANITIZED_FQDN}=${ip_norm}"
    resp="$(add_record "${domain_id}" "${sub}" "${rtype}" "${ip_norm}" "${LINE_ID}" "${TTL}")"
    code="$(jq -r 'try .code catch 0' <<< "${resp}")"
    msg="$(jq -r 'try .msg  catch empty' <<< "${resp}")"
    if [[ "${code}" = "0" ]]; then
      log "新增成功（${rtype}）"
    else
      log "新增失败（${rtype}）：code=${code} msg=${msg} resp=${resp}"
      echo "新增 ${rtype} 记录失败：${msg:-unknown}" >&2
      return 1
    fi
  fi
}

########################################
# 主程序
########################################
main() {
  log "===== dnsmgr-ddns 启动：${SANITIZED_FQDN} ====="

  if [[ "${ENABLE_IPV4}" != "true" && "${ENABLE_IPV6}" != "true" ]]; then
    log "IPv4 与 IPv6 均被禁用，流程结束"
    echo "IPv4 与 IPv6 均被禁用，未进行任何更新。"
    exit 0
  fi

  # 1) 找主域 & 子域
  local domain_json DOMAIN_ID DOMAIN_NAME SUBDOMAIN
  domain_json="$(find_domain "${SANITIZED_FQDN}")"
  if [[ -z "${domain_json}" || "${domain_json}" == "null" ]]; then
    log "错误：未找到 ${SANITIZED_FQDN} 对应的主域"
    echo "未在可管理域名中找到 ${SANITIZED_FQDN} 对应主域，退出（详见日志）。" >&2
    exit 1
  fi

  DOMAIN_ID="$(jq -r '.id'   <<< "${domain_json}")"
  DOMAIN_NAME="$(jq -r '.name' <<< "${domain_json}")"
  DOMAIN_NAME="$(trim "${DOMAIN_NAME}")"
  DOMAIN_NAME="${DOMAIN_NAME%.}"
  DOMAIN_NAME="${DOMAIN_NAME,,}"

  if [[ -z "${DOMAIN_ID}" || -z "${DOMAIN_NAME}" || "${DOMAIN_NAME}" == "null" ]]; then
    log "错误：domain_json 解析失败：${domain_json}"
    echo "主域解析失败（详见日志）。" >&2
    exit 1
  fi

  if [[ "${SANITIZED_FQDN}" == "${DOMAIN_NAME}" ]]; then
    SUBDOMAIN="@"
  else
    SUBDOMAIN="${SANITIZED_FQDN%."${DOMAIN_NAME}"}"
  fi
  log "已解析主域：id=${DOMAIN_ID}, name=${DOMAIN_NAME}, sub=${SUBDOMAIN}"

  # 2) TTL 不低于平台最小值
  local min_ttl_str
  min_ttl_str="$(get_domain_min_ttl "${DOMAIN_ID}")" || true
  if [[ -n "${min_ttl_str}" && "${min_ttl_str}" =~ ^[0-9]+$ ]]; then
    if (( TTL < min_ttl_str )); then
      log "将 TTL 从 ${TTL} 调整为平台最小值 ${min_ttl_str}"
      TTL="${min_ttl_str}"
    fi
  fi

  # 3) 获取公网 IP
  local IPV4="" IPV6=""
  if [[ "${ENABLE_IPV4}" == "true" ]]; then
    IPV4="$(trim "$(get_ipv4)")"
    if is_ipv4 "${IPV4}"; then
      log "检测到 IPv4：${IPV4}"
    else
      IPV4=""
      log "未检测到 IPv4"
    fi
  else
    log "已禁用 IPv4 处理，跳过"
  fi

  if [[ "${ENABLE_IPV6}" == "true" ]]; then
    IPV6="$(trim "$(get_ipv6)")"
    if is_ipv6 "${IPV6}"; then
      log "检测到 IPv6：${IPV6}"
    else
      IPV6=""
      log "未检测到 IPv6"
    fi
  else
    log "已禁用 IPv6 处理，跳过"
  fi

  # 4) 更新（仅在变化时）
  if [[ "${ENABLE_IPV4}" == "true" ]]; then
    do_one_type "A" "${IPV4}" "${DOMAIN_ID}" "${SUBDOMAIN}" || true
  fi
  if [[ "${ENABLE_IPV6}" == "true" ]]; then
    do_one_type "AAAA" "${IPV6}" "${DOMAIN_ID}" "${SUBDOMAIN}" || true
  fi

  log "===== dnsmgr-ddns 完成：${SANITIZED_FQDN} ====="
  echo "DDNS 更新完成（详见 ${LOG_FILE}）。"
}

main "$@"

```

