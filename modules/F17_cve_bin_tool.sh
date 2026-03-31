#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Based on the generated SBOM this module extracts known vulnerabilities
#               via cve-bin-tool
# shellcheck disable=SC2153

# ==========================================================================================
# 模块说明：F17 - 基于 SBOM 的最终漏洞聚合器
#
# 本模块利用前序模块（F15 等）生成的 SBOM（软件物料清单）文件，
# 通过 cve-bin-tool 工具对每个软件组件执行 CVE 漏洞扫描。
# 同时整合来自 S26（Linux 内核漏洞）、S36（lighttpd）、S118（BusyBox）
# 等专项模块的已验证漏洞数据，避免重复检测。
# 最终生成 CycloneDX 格式的 VEX（漏洞可利用性交换）JSON 报告。
#
# 主要函数列表：
#   F17_cve_bin_tool          - 模块主入口，调度所有子任务
#   sbom_preprocessing_threader - SBOM 条目预处理（多线程），去重过滤
#   cve_bin_tool_threader     - 调用 cve-bin-tool 执行 CVE 检测（多线程）
#   tear_down_cve_threader    - 解析 CVE 结果，查找利用代码，生成 VEX 条目
#   get_kernel_s25_data       - 从 S25 模块日志中加载内核已知漏洞利用列表
#   get_epss_data             - 查询 EPSS（漏洞利用预测评分系统）数据
#   backup_vex_file           - 重新扫描时备份已有 VEX 文件
# ==========================================================================================

# ==========================================================================================
# F17_cve_bin_tool - 模块主入口函数
#
# 功能：
#   1. 读取 EMBA 生成的 SBOM JSON 文件
#   2. 对每个 SBOM 组件进行预处理（去重、过滤无效条目）
#   3. 等待 CVE 数据库导入完成（最长等待约 2 分钟）
#   4. 对每个有效组件并发调用 cve_bin_tool_threader 进行 CVE 扫描
#      - BusyBox、lighttpd、Linux Kernel 等组件直接复用专项模块的结果
#   5. 将所有 CVE JSON 条目合并生成最终的 VEX JSON 文件
#      - EMBA_sbom_vex_only.json       仅包含漏洞信息的 VEX 文件
#      - EMBA_cyclonedx_vex_sbom.json  完整 SBOM + VEX 合并文件
# ==========================================================================================
F17_cve_bin_tool() {
  # 初始化模块日志和标题
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"

  # 输出模块前置报告（如模块说明、依赖检查等）
  pre_module_reporter "${FUNCNAME[0]}"

  # 优先使用 F15 模块生成的 SBOM；若 F15 被禁用，则回退到 s08_package_mgmt_extractor.csv
  local lEMBA_SBOM_JSON="${EMBA_SBOM_JSON}"   # SBOM JSON 文件路径（全局变量）
  local lSBOM_ARR=()                           # 存放 SBOM 所有组件条目的数组
  local lSBOM_ENTRY=""                         # 当前正在处理的单个 SBOM 组件
  local lWAIT_PIDS_F17_ARR=()                  # 记录各并发子进程 PID，用于等待完成
  local lVEX_JSON_ENTRIES_ARR=()               # 找到的所有 VEX JSON 文件路径数组
  local lVEX_FILE_ID=0                         # VEX 文件索引（用于判断是否为最后一项）
  local lVEX_FILE=""                           # 当前处理的 VEX JSON 文件路径
  local lNEG_LOG=0                             # 负日志标志（0=无结果，1=有结果）
  # 将最大并发线程数翻倍，因为预处理任务相对轻量
  local MAX_MOD_THREADS=$((MAX_MOD_THREADS*2))

  # 创建输出子目录：json（VEX 条目）、cve_sum（CVE 汇总）、exploit（利用代码副本）
  mkdir "${LOG_PATH_MODULE}/json/" || true
  mkdir "${LOG_PATH_MODULE}/cve_sum/" || true
  mkdir "${LOG_PATH_MODULE}/exploit/" || true

  print_output "[*] Loading SBOM ..." "no_log"

  # 若 SBOM 文件不存在，则直接退出本模块
  if ! [[ -f "${lEMBA_SBOM_JSON}" ]]; then
    print_error "[-] No SBOM available!"
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  # 将 SBOM JSON 数组中的每个组件解析为 Bash 数组元素（每行一个紧凑 JSON 对象）
  readarray -t lSBOM_ARR < <(jq --compact-output '.components[]' "${lEMBA_SBOM_JSON}" || print_error "[-] SBOM loading error - Vulnerability analysis not available")

  sub_module_title "Software inventory overview"
  print_output "[*] Analyzing ${#lSBOM_ARR[@]} SBOM components ..." "no_log"

  # -----------------------------------------------------------------------
  # 第一轮处理：预处理 SBOM 条目
  #   主要目的：
  #   1. 去除重复条目（同一产品+版本组合）
  #   2. 过滤掉 "unhandled_file" 类型的条目
  #   3. 生成 HTML 报告所需的初步概览
  # -----------------------------------------------------------------------
  local lWAIT_PIDS_TEMP=()
  [[ ! -d "${LOG_PATH_MODULE}/tmp/" ]] && mkdir -p "${LOG_PATH_MODULE}/tmp/"
  for lSBOM_ENTRY in "${lSBOM_ARR[@]}"; do
    # 每个条目作为独立子进程并发处理，提高效率
    sbom_preprocessing_threader "${lSBOM_ENTRY}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_TEMP+=( "${lTMP_PID}" )
    # 控制并发进程数量，防止进程过多占用系统资源（最大为 MAX_MOD_THREADS 的 2 倍）
    max_pids_protection $((2*"${MAX_MOD_THREADS}")) lWAIT_PIDS_TEMP
    local lNEG_LOG=1  # 标记已有组件需要处理
  done
  # 等待所有预处理子进程结束
  wait_for_pid "${lWAIT_PIDS_TEMP[@]}"

  # 将各子进程输出的临时文件合并为一个统一的预处理结果文件
  cat "${LOG_PATH_MODULE}/tmp/sbom_entry_preprocessed."* > "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp" || print_output "[-] Some pre-processing error occured"

  print_bar

  # 若预处理后没有任何有效组件，直接退出
  if ! [[ -f "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp" ]]; then
    print_output "[*] No SBOM components for further analysis detected"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  sub_module_title "Vulnerability overview"

  # -----------------------------------------------------------------------
  # 等待 CVE 数据库导入完成
  #   检查标志文件 ${TMP_DIR}/tmp_state_data.log 是否存在
  #   每 5 秒轮询一次，最多等待约 2 分钟（24 次 × 5 秒）
  #   超时后继续尝试执行，期望数据库已经就绪
  # -----------------------------------------------------------------------
  local lCNT=0
  while ! [[ -f "${TMP_DIR}/tmp_state_data.log" ]]; do
    print_output "[*] Waiting for CVE database ..." "no_log"
    lCNT=$((lCNT+1))
    if [[ "${lCNT}" -gt 24 ]]; then
      print_output "[-] CVE database not prepared in time ... trying to proceed"
      break
    fi
    sleep 5
  done

  # -----------------------------------------------------------------------
  # 第二轮处理：对预处理后的 SBOM 条目执行 CVE 扫描
  # -----------------------------------------------------------------------
  while read -r lSBOM_ENTRY; do
    local lBOM_REF=""        # BOM 引用 ID（在 SBOM 中唯一标识该组件）
    local lORIG_SOURCE=""    # 来源标识（如 package_manager、binary_analysis 等）
    local lVENDOR_ARR=()     # 供应商名称数组（可能有多个别名）
    local lPRODUCT_ARR=()    # 产品名称数组（可能有多个别名）
    local lPRODUCT_VERSION="" # 产品版本字符串
    local lPRODUCT_NAME=""   # 产品名称（SBOM 中的 name 字段）

    # 从 JSON 中提取产品名称
    lPRODUCT_NAME=$(jq --raw-output '.name' <<< "${lSBOM_ENTRY}")

    # 从 SBOM 属性中提取所有可能的供应商名称（vendor_name 属性）
    mapfile -t lVENDOR_ARR < <(jq --raw-output '.properties[] | select(.name | test("vendor_name")) | .value' <<< "${lSBOM_ENTRY}")
    # 若未找到任何供应商，使用占位符 "NOTDEFINED"
    if [[ "${#lVENDOR_ARR[@]}" -eq 0 ]]; then
      lVENDOR_ARR+=("NOTDEFINED")
    fi

    # 从 SBOM 属性中提取所有可能的产品名称（product_name 属性）
    mapfile -t lPRODUCT_ARR < <(jq --raw-output '.properties[] | select(.name | test("product_name")) | .value' <<< "${lSBOM_ENTRY}")
    # 若未找到任何产品名，使用 SBOM 中的 name 字段
    if [[ "${#lPRODUCT_ARR[@]}" -eq 0 ]]; then
      lPRODUCT_ARR+=("${lPRODUCT_NAME}")
    fi

    # 提取版本号
    lPRODUCT_VERSION=$(jq --raw-output '.version' <<< "${lSBOM_ENTRY}")

    # 去重检查：若该 vendor/product/version 组合已经处理过，跳过
    if (grep -q "${lVENDOR_ARR[*]//\\n};${lPRODUCT_ARR[*]//\\n};${lPRODUCT_VERSION}" "${LOG_PATH_MODULE}/sbom_entry_processed.tmp" 2>/dev/null); then
      continue
    fi
    # 记录当前条目到已处理列表，防止后续重复
    echo "${lVENDOR_ARR[*]//\\n};${lPRODUCT_ARR[*]//\\n};${lPRODUCT_VERSION}" >> "${LOG_PATH_MODULE}/sbom_entry_processed.tmp"

    # -------------------------------------------------------------------
    # 特殊组件处理：BusyBox
    #   若组件为 busybox 且 S118 模块已生成验证结果，直接复用 S118 的数据，
    #   无需重新调用 cve-bin-tool，避免重复检测
    # -------------------------------------------------------------------
    if [[ "${lPRODUCT_NAME}" == "busybox" ]] && [[ -s "${S118_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] BusyBox results from s118 detected ... no CVE detection needed" "no_log"
      # 复制 S118 已生成的 CSV、JSON、CVE 汇总、利用代码等文件到本模块目录
      cp "${S118_LOG_DIR}/"*"_${lPRODUCT_NAME}_${lPRODUCT_VERSION}.csv" "${LOG_PATH_MODULE}" 2>/dev/null || true
      cp "${S118_LOG_DIR}/json/"* "${LOG_PATH_MODULE}/json/" 2>/dev/null || true
      cp "${S118_LOG_DIR}/cve_sum/"* "${LOG_PATH_MODULE}/cve_sum/" 2>/dev/null || true
      cp "${S118_LOG_DIR}/exploit/"* "${LOG_PATH_MODULE}/exploit/" 2>/dev/null || true
      # 从 S118 的 vuln_summary.txt 中提取对应的组件摘要行，追加到本模块汇总文件
      if [[ -f "${S118_LOG_DIR}/vuln_summary.txt" ]]; then
        lBB_ENTRY_TO_COPY=$(grep "Component details:.*${lPRODUCT_NAME}.*:.*${lPRODUCT_VERSION}.*:" "${S118_LOG_DIR}"/vuln_summary.txt || true)
        echo "${lBB_ENTRY_TO_COPY}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
      fi
      local lBIN_LOG=""
      # 查找该组件对应的完成日志文件
      lBIN_LOG=$(find "${LOG_PATH_MODULE}"/cve_sum/ -name "*_${lPRODUCT_NAME}_${lPRODUCT_VERSION}_finished.txt" | sort -u | head -1)

      # 将该组件的详细日志追加到模块主日志并跳过 CVE 检测
      if [[ -f "${lBIN_LOG}" ]]; then
        tee -a "${LOG_FILE}" < "${lBIN_LOG}"
        continue
      else
        print_error "[-] S118 Busybox details missing ... continue in default mode"
      fi
    # -------------------------------------------------------------------
    # 特殊组件处理：lighttpd
    #   若组件为 lighttpd 且 S36 模块已生成验证结果，直接复用 S36 的数据
    # -------------------------------------------------------------------
    elif [[ "${lPRODUCT_NAME}" == "lighttpd" ]] && [[ -s "${S36_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] lighttpd results from s36 detected ... no CVE detection needed" "no_log"
      # 复制 S36 已生成的各类结果文件到本模块目录
      cp "${S36_LOG_DIR}/"*"_${lPRODUCT_NAME}_${lPRODUCT_VERSION}.csv" "${LOG_PATH_MODULE}" || print_error "[-] lighttpd CVE log copy process failed"
      cp "${S36_LOG_DIR}/json/"* "${LOG_PATH_MODULE}/json/" || print_error "[-] lighttpd CVE log copy process failed"
      cp "${S36_LOG_DIR}/cve_sum/"* "${LOG_PATH_MODULE}/cve_sum/" || print_error "[-] lighttpd CVE log copy process failed"
      cp "${S36_LOG_DIR}/exploit/"* "${LOG_PATH_MODULE}/exploit/" 2>/dev/null || print_error "[-] lighttpd CVE log copy process failed"
      # 追加 lighttpd 组件汇总信息到漏洞摘要文件
      if [[ -f "${S36_LOG_DIR}/vuln_summary.txt" ]]; then
        lBB_ENTRY_TO_COPY=$(grep "Component details:.*${lPRODUCT_NAME}.*:.*${lPRODUCT_VERSION}.*:" "${S36_LOG_DIR}"/vuln_summary.txt || true)
        echo "${lBB_ENTRY_TO_COPY}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
      fi
      local lBIN_LOG=""
      lBIN_LOG=$(find "${LOG_PATH_MODULE}"/cve_sum/ -name "*_${lPRODUCT_NAME}_${lPRODUCT_VERSION}_finished.txt" | sort -u | head -1)

      # 将 lighttpd 详细日志追加到主日志并跳过 CVE 检测
      if [[ -f "${lBIN_LOG}" ]]; then
        tee -a "${LOG_FILE}" < "${lBIN_LOG}"
        continue
      else
        print_error "[-] S36 lighttpd details missing ... continue in default mode"
      fi
    # -------------------------------------------------------------------
    # 特殊组件处理：Linux 内核
    #   若组件名以 "linux_kernel" 开头且 S26 模块已生成验证结果，
    #   直接复用 S26（内核漏洞验证模块）的数据
    # -------------------------------------------------------------------
    elif [[ "${lPRODUCT_NAME}" == "linux_kernel"* ]] && [[ -s "${S26_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] Possible Linux kernel results from s26 detected ... no CVE detection needed" "no_log"
      # 复制 S26 已生成的各类结果文件到本模块目录
      cp "${S26_LOG_DIR}/"*"_${lPRODUCT_NAME}_${lPRODUCT_VERSION}.csv" "${LOG_PATH_MODULE}" || print_error "[-] Linux Kernel CVE log copy process failed"
      cp "${S26_LOG_DIR}/json/"* "${LOG_PATH_MODULE}/json/" || print_error "[-] Linux Kernel CVE log copy process failed"
      cp "${S26_LOG_DIR}/cve_sum/"* "${LOG_PATH_MODULE}/cve_sum/" || print_error "[-] Linux Kernel CVE log copy process failed"
      cp "${S26_LOG_DIR}/exploit/"* "${LOG_PATH_MODULE}/exploit/" 2>/dev/null || print_error "[-] Linux Kernel CVE log copy process failed"
      # 追加内核组件汇总信息到漏洞摘要文件
      if [[ -f "${S26_LOG_DIR}/vuln_summary.txt" ]]; then
        lBB_ENTRY_TO_COPY=$(grep "Component details:.*${lPRODUCT_NAME}.*:.*${lPRODUCT_VERSION}.*:" "${S26_LOG_DIR}"/vuln_summary.txt || true)
        echo "${lBB_ENTRY_TO_COPY}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
      fi
      local lBIN_LOG=""
      lBIN_LOG=$(find "${LOG_PATH_MODULE}"/cve_sum/ -name "*_${lPRODUCT_NAME}_${lPRODUCT_VERSION}_finished.txt" | sort -u | head -1)

      # 将内核详细日志追加到主日志并跳过 CVE 检测
      if [[ -f "${lBIN_LOG}" ]]; then
        tee -a "${LOG_FILE}" < "${lBIN_LOG}"
        continue
      else
        print_error "[-] S26 Linux Kernel details missing ... continue in default mode"
      fi
    fi

    # 提取 BOM 引用 ID 和原始来源标识
    lBOM_REF=$(jq --raw-output '."bom-ref"' <<< "${lSBOM_ENTRY}" || print_error "[-] BOM_REF failed to extract from ${lSBOM_ENTRY}")
    lORIG_SOURCE=$(jq --raw-output '.group' <<< "${lSBOM_ENTRY}" || print_error "[-] ORIG_SOURCE failed to extract from ${lSBOM_ENTRY}")

    # 以子进程方式并发调用 CVE 检测线程函数
    cve_bin_tool_threader "${lBOM_REF}" "${lPRODUCT_VERSION}" "${lORIG_SOURCE}" lVENDOR_ARR lPRODUCT_ARR &
    local lTMP_PID="$!"
    # 注册子进程 PID，以便主进程在退出时可以终止所有子进程
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_F17_ARR+=( "${lTMP_PID}" )
    # 控制并发数量不超过 MAX_MOD_THREADS
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_F17_ARR
  done < "${LOG_PATH_MODULE}/sbom_entry_preprocessed.tmp"

  # 等待所有 CVE 检测子进程结束
  wait_for_pid "${lWAIT_PIDS_F17_ARR[@]}"

  print_output "[*] Generating final VEX vulnerability json ..." "no_log"

  # -----------------------------------------------------------------------
  # 重新扫描模式（RESCAN_SBOM=1）处理
  #   在重新扫描时，将已有的 VEX 文件备份为 .previous.json，
  #   然后用新生成的文件覆盖标准路径文件名
  # -----------------------------------------------------------------------
  if [[ "${RESCAN_SBOM:-0}" -eq 1 ]]; then
    print_output "[*] Backing up existing VEX files as previous versions" "no_log"

    # 备份仅漏洞信息的 VEX 文件
    if [[ -f "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" ]]; then
      backup_vex_file "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"
    else
      print_output "[-] No VEX only json file found"
    fi
    # 备份完整 SBOM+VEX 合并文件
    if [[ -f "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json" ]]; then
      backup_vex_file "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json"
    else
      print_output "[-] No VEX SBOM json file found"
    fi

    # 删除上次生成的临时中间文件（如果存在）
    if [[ -f "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json" ]]; then
      rm "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
    fi
  fi

  # -----------------------------------------------------------------------
  # 构建最终的 VEX JSON 文件
  #
  # 步骤：
  #   1. 收集 json/ 目录下所有 .json 文件（每个文件是一个 CVE 的 VEX 条目）
  #   2. 将所有条目合并为 JSON 数组（用逗号分隔，最后一项不加逗号）
  #   3. 生成 EMBA_sbom_vex_only.json（符合 CycloneDX 1.5 VEX 标准）
  #   4. 将漏洞信息插入到 EMBA_cyclonedx_sbom.json 的空 vulnerabilities 占位符处，
  #      生成完整的 EMBA_cyclonedx_vex_sbom.json
  # -----------------------------------------------------------------------
  mapfile -t lVEX_JSON_ENTRIES_ARR < <(find "${LOG_PATH_MODULE}/json/" -name "*.json")
  print_output "[*] Building final VEX - Vulnerability Exploitability eXchange" "no_log"
  if [[ "${#lVEX_JSON_ENTRIES_ARR[@]}" -gt 0 ]]; then
    local lNEG_LOG=1
    # 写入 JSON 数组开头标记
    echo "\"vulnerabilities\": [" > "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"

    for lVEX_FILE_ID in "${!lVEX_JSON_ENTRIES_ARR[@]}"; do
      lVEX_FILE="${lVEX_JSON_ENTRIES_ARR["${lVEX_FILE_ID}"]}"
      if [[ -s "${lVEX_FILE}" ]]; then
        # 验证 JSON 文件是否合法（通过 json_pp 解析测试）
        if (json_pp < "${lVEX_FILE}" &> /dev/null); then
          cat "${lVEX_FILE}" >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
        else
          print_output "[!] WARNING: SBOM component ${lVEX_FILE} failed to validate with json_pp"
          continue
        fi
      else
        print_output "[!] WARNING: SBOM component ${lVEX_FILE} failed to decode"
        continue
      fi
      # 除最后一个条目外，每个条目后面追加逗号（构造合法 JSON 数组）
      if [[ $((lVEX_FILE_ID+1)) -lt "${#lVEX_JSON_ENTRIES_ARR[@]}" ]]; then
        echo -n "," >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
      fi
    done

    # 写入 JSON 数组结束标记
    echo -n "]" >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
    # 去掉换行符，将临时文件转换为单行 JSON（方便后续 sed 插入）
    tr -d '\n' < "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json" > "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"

    if [[ -f "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" ]]; then
      sub_module_title "VEX - Vulnerability Exploitability eXchange"
      print_output "[+] VEX data in json format is available" "" "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"

      # 将 VEX 漏洞数据插入到 CycloneDX SBOM 的 "vulnerabilities": [] 占位符处
      # 生成完整的 SBOM+VEX 合并文件
      sed -e '/\"vulnerabilities\": \[\]/{r '"${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" -e 'd;}' "${SBOM_LOG_PATH}/EMBA_cyclonedx_sbom.json" > "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json" || print_error "[-] SBOM - VEX merge failed"

      # 为 VEX only 文件添加 CycloneDX 1.5 标准所需的头部字段
      # 参考：https://github.com/CycloneDX/bom-examples/blob/master/VEX/vex.json
      sed -i '1i "version": 1,' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
      sed -i '1i "specVersion": "1.5",' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
      sed -i '1i "bomFormat": "CycloneDX",' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
      # 在文件最开头添加 JSON 对象起始花括号
      sed -i '1i {' "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"

      # 在文件末尾追加 JSON 对象结束花括号
      echo '}' >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json" || print_error "[-] VEX only JSON preparation failed"
    fi
    # 输出完整 SBOM+VEX 文件的提示信息
    if [[ -f "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json" ]]; then
      print_output "[+] CycloneDX SBOM with VEX data in JSON format is ready" "" "${SBOM_LOG_PATH}/EMBA_cyclonedx_vex_sbom.json"
    fi
  fi

  # 记录模块结束日志
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

# ==========================================================================================
# sbom_preprocessing_threader - SBOM 条目预处理线程函数
#
# 功能：
#   对单个 SBOM 组件条目进行预处理：
#   1. 过滤掉来源为 "unhandled_file" 的条目（无法处理的文件类型）
#   2. 过滤掉没有版本信息的条目（无版本则无法进行 CVE 查询）
#   3. 去除重复的 产品名+版本 组合
#   4. 将通过过滤的条目写入临时文件，并向 HTML 报告输出初始概览信息
#
# 参数：
#   $1 - lSBOM_ENTRY: 单个 SBOM 组件的 JSON 字符串
#
# 输出：
#   ${LOG_PATH_MODULE}/tmp/sbom_entry_preprocessed.${lBOM_REF} - 预处理结果临时文件
# ==========================================================================================
sbom_preprocessing_threader() {
  local lSBOM_ENTRY="${1:-}"

  local lBOM_REF=""          # 组件在 SBOM 中的唯一引用 ID
  local lORIG_SOURCE=""      # 组件来源（如 binary_analysis、package_manager 等）
  local lVENDOR_ARR=()       # 供应商名称数组
  local lPRODUCT_ARR=()      # 产品名称数组
  local lPRODUCT_VERSION=""  # 版本字符串
  local lPRODUCT_NAME=""     # 产品名称

  # 提取组件来源字段（group 字段在 SBOM 中表示来源分类）
  lORIG_SOURCE=$(jq --raw-output '.group' <<< "${lSBOM_ENTRY}")

  # 跳过 "unhandled_file" 类型：这类条目是 EMBA 无法识别格式的文件，没有版本信息
  if [[ "${lORIG_SOURCE}" == "unhandled_file" ]]; then
    return
  fi

  # 提取版本信息
  lPRODUCT_VERSION=$(jq --raw-output '.version' <<< "${lSBOM_ENTRY}")

  # 版本为空时跳过（无版本则无法匹配 CVE）
  if [[ -z "${lPRODUCT_VERSION}" ]]; then
    return
  fi

  # 提取产品名称（仅用于重复检查，不用于 CVE 查询）
  lPRODUCT_NAME=$(jq --raw-output '.name' <<< "${lSBOM_ENTRY}")

  # 提取所有可能的供应商名称（SBOM properties 中 vendor_name 属性的值）
  mapfile -t lVENDOR_ARR < <(jq --raw-output '.properties[] | select(.name | test("vendor_name")) | .value' <<< "${lSBOM_ENTRY}")
  # 若无供应商信息，使用占位符 "NOTDEFINED"
  if [[ "${#lVENDOR_ARR[@]}" -eq 0 ]]; then
    lVENDOR_ARR+=("NOTDEFINED")
  fi

  # 提取所有可能的产品名称（SBOM properties 中 product_name 属性的值）
  mapfile -t lPRODUCT_ARR < <(jq --raw-output '.properties[] | select(.name | test("product_name")) | .value' <<< "${lSBOM_ENTRY}")
  # 若无产品别名，直接使用 SBOM name 字段
  if [[ "${#lPRODUCT_ARR[@]}" -eq 0 ]]; then
    lPRODUCT_ARR+=("${lPRODUCT_NAME}")
  fi

  # 提取 BOM 引用 ID（用于生成唯一的临时文件名）
  lBOM_REF=$(jq --raw-output '."bom-ref"' <<< "${lSBOM_ENTRY}")

  # 生成 HTML 报告的锚点 ID（用于报告内部跳转链接）
  # 格式：cve_ + 产品名（去除引号）前 20 字符 + _ + 版本
  local lANCHOR=""
  lANCHOR="${lPRODUCT_ARR[0]//\'}_${lPRODUCT_VERSION}"
  lANCHOR="cve_${lANCHOR:0:20}"

  # 跨子进程去重检查：检查是否已有其他并发进程处理了相同的 产品名+版本 组合
  if (grep -q "\"name\":\"${lPRODUCT_NAME}\",\"version\":\"${lPRODUCT_VERSION}\"" "${LOG_PATH_MODULE}/tmp/sbom_entry_preprocessed.*" 2>/dev/null); then
    return
  fi

  # 将当前条目的 JSON 写入以 BOM 引用命名的临时文件（便于后续合并）
  echo "${lSBOM_ENTRY}" >> "${LOG_PATH_MODULE}/tmp/sbom_entry_preprocessed.${lBOM_REF}"
  # 向日志和 HTML 报告输出该组件的概览信息（产品、供应商、版本、BOM 引用）
  print_output "[*] Vulnerability details for ${ORANGE}${lPRODUCT_ARR[0]//\'/}${NC} - vendor ${ORANGE}${lVENDOR_ARR[0]//\'/}${NC} - version ${ORANGE}${lPRODUCT_VERSION}${NC} - BOM reference ${ORANGE}${lBOM_REF}${NC}" "" "f17#${lANCHOR}"
}


# ==========================================================================================
# cve_bin_tool_threader - CVE 检测线程函数
#
# 功能：
#   1. 为指定组件构造 cve-bin-tool 所需的输入 CSV 文件
#      （含 product/vendor/version/bom-ref 等字段的组合，含供应商和不带供应商两种查询）
#   2. 调用 cve-bin-tool（Python 工具）离线扫描 CVE
#   3. 解析 cve-bin-tool 输出的 CSV 结果，并发调用 tear_down_cve_threader
#      对每条 CVE 记录进行漏洞详情分析、利用代码查找、VEX 条目生成
#   4. 汇总统计 CVE 数量、漏洞利用数量，生成每个组件的最终漏洞报告
#
# 参数：
#   $1 - lBOM_REF      : SBOM 中该组件的唯一引用 ID
#   $2 - lVERS         : 组件版本字符串
#   $3 - lORIG_SOURCE  : 来源标识（如 binary_analysis、package_manager 等）
#   $4 - lrVENDOR_ARR  : 供应商名称数组（通过 nameref 引用传递）
#   $5 - lrPRODUCT_ARR : 产品名称数组（通过 nameref 引用传递）
#
# 输出文件（示例）：
#   ${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv                          - cve-bin-tool 输入文件
#   ${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.csv   - cve-bin-tool 输出结果
#   ${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}_finished.txt - 最终报告
#   ${LOG_PATH_MODULE}/vuln_summary.txt                             - 所有组件漏洞汇总表
# ==========================================================================================
cve_bin_tool_threader() {
  local lBOM_REF="${1:-}"        # BOM 引用 ID
  local lVERS="${2:-}"           # 版本号
  local lORIG_SOURCE="${3:-}"    # 来源标识
  local -n lrVENDOR_ARR="${4:-}" # 供应商数组（nameref 引用，避免数组拷贝）
  local -n lrPRODUCT_ARR="${5:-}" # 产品数组（nameref 引用）
  local lWAIT_PIDS_F17_ARR_2=() # 本层并发子进程 PID 数组

  # 若产品名称数组为空，无法构造 CVE 查询，直接返回
  if [[ "${#lrPRODUCT_ARR[@]}" -eq 0 ]]; then
    print_output "[-] No product name available for ${lVENDOR:-NOTDEFINED},${lVERS},${lBOM_REF}" "no_log"
    return
  fi

  # cve-bin-tool 的 CLI 入口点路径
  local lCVE_BIN_TOOL="/external/cve-bin-tool/cve_bin_tool/cli.py"

  # 写入 CSV 文件头（cve-bin-tool 输入格式要求）
  write_log "product,vendor,version,bom-ref" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"

  # 遍历所有供应商和产品名称组合，构造多条查询行
  for lVENDOR in "${lrVENDOR_ARR[@]}"; do
    # 去除供应商名称首尾的单引号（来自 SBOM 属性值的转义）
    lVENDOR="${lVENDOR#\'}"
    lVENDOR="${lVENDOR%\'}"
    for lPROD in "${lrPRODUCT_ARR[@]}"; do
      # 去除产品名称首尾的单引号
      lPROD="${lPROD#\'}"
      lPROD="${lPROD%\'}"

      # 安全过滤：当供应商未知且产品名长度小于 4 时，跳过
      # 原因：过短的产品名在不指定供应商时会产生大量误报
      if [[ "${lVENDOR}" == "NOTDEFINED" && "${#lPROD}" -lt 4 ]]; then
        print_output "[-] WARNING: No vendor (${lVENDOR}) identified and a short product name ${lPROD} -> CVE queries would be very false positive prone."
        print_output "[-] WARNING: ${lPROD} -> No CVE queries performed."
        continue
      fi

      # 写入带供应商信息的查询行（精确匹配）
      write_log "${lPROD},${lVENDOR:-NOTDEFINED},${lVERS},${lBOM_REF}" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"

      # CPE 中的供应商信息往往不一致，额外添加一条不指定供应商的查询行（扩大覆盖范围）
      if [[ "${lVENDOR}" != "NOTDEFINED" ]]; then
        write_log "${lPROD},NOTDEFINED,${lVERS},${lBOM_REF}" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"
      fi

    done
  done

  # 若 CSV 文件未成功创建，跳过本组件的 CVE 检测
  if ! [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" ]]; then
    print_output "[-] No tmp vendor/product file for ${lrVENDOR_ARR[*]}/${lrPRODUCT_ARR[*]} for cve-bin-tool generated"
    return
  fi

  # 取第一个产品名作为主产品名（用于文件命名），并去除首尾单引号
  lPRODUCT_NAME="${lrPRODUCT_ARR[0]}"
  lPRODUCT_NAME="${lPRODUCT_NAME#\'}"
  lPRODUCT_NAME="${lPRODUCT_NAME%\'}"

  # 确保输出子目录存在
  if ! [[ -d "${LOG_PATH_MODULE}/cve_sum/" ]]; then
    mkdir "${LOG_PATH_MODULE}/cve_sum/"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}/json/" ]]; then
    mkdir "${LOG_PATH_MODULE}/json/"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}/exploit/" ]]; then
    mkdir "${LOG_PATH_MODULE}/exploit/"
  fi

  # -----------------------------------------------------------------------
  # 调用 cve-bin-tool 执行离线 CVE 扫描
  # 参数说明：
  #   -i  指定输入 CSV 文件（product/vendor/version 列表）
  #   --disable-version-check   不检查 cve-bin-tool 自身版本更新
  #   --disable-validation-check 不进行数据库完整性校验（加速扫描）
  #   --no-0-cve-report         当没有发现 CVE 时不生成空报告文件
  #   --offline                 使用本地 CVE 数据库（不联网更新）
  #   -f csv                    输出格式为 CSV
  #   -o 指定输出文件名（不含扩展名，工具自动添加 .csv）
  # -----------------------------------------------------------------------
  python3 "${lCVE_BIN_TOOL}" -i "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" --disable-version-check --disable-validation-check --no-0-cve-report --offline -f csv -o "${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}" || true

#  if [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" ]]; then
#    rm "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" || true
#  fi

  # -----------------------------------------------------------------------
  # 解析 cve-bin-tool 输出的 CSV 结果
  #   对每一条 CVE 记录并发调用 tear_down_cve_threader 进行详细处理：
  #   - 查找可用的利用代码（EDB、MSF、Snyk、PacketStorm、RouterSploit）
  #   - 检查内核 CVE 验证状态（S26 模块结果）
  #   - 检查 BusyBox CVE 验证状态（S118 模块结果）
  #   - 查询 EPSS 评分、KEV 状态
  #   - 生成 VEX JSON 条目
  # -----------------------------------------------------------------------
  if [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.csv" ]]; then
    print_output "[*] Identification of possible Exploits, EPSS and further details ..." "no_log"
    while read -r lCVE_LINE; do
      # 格式：BOM_REF,ORIG_SOURCE 前缀 + cve-bin-tool CSV 输出行（跳过标题行，按第4列去重排序）
      tear_down_cve_threader "${lBOM_REF},${lORIG_SOURCE},${lCVE_LINE}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_F17_ARR_2+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_F17_ARR_2
    done < <(tail -n +2 "${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.csv" | sort -u -t, -k4,4)
    # tail -n +2：跳过 CSV 标题行
    # sort -u -t, -k4,4：按第4列（CVE ID）去重排序，避免重复处理同一个 CVE
  fi
  # 等待所有 CVE 详情处理子进程完成
  wait_for_pid "${lWAIT_PIDS_F17_ARR_2[@]}"

  # -----------------------------------------------------------------------
  # 生成该组件的最终漏洞汇总日志
  # -----------------------------------------------------------------------
  local lBIN_LOG="${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}_finished.txt"
  write_log "" "${lBIN_LOG}"

  # 生成 HTML 报告锚点
  local lANCHOR=""
  lANCHOR="${lPRODUCT_NAME//\'}_${lVERS}"
  lANCHOR="cve_${lANCHOR:0:20}"
  write_log "[*] Vulnerability details for ${ORANGE}${lPRODUCT_NAME}${NC} / version ${ORANGE}${lVERS}${NC} / source ${ORANGE}${lORIG_SOURCE}${NC}:" "${lBIN_LOG}"
  write_anchor "${lANCHOR}" "${lBIN_LOG}"

  # 统计该组件的 CVE 数量和漏洞利用数量
  local lEXPLOIT_COUNTER_VERSION=0  # 含利用代码的 CVE 数量
  local lCVE_COUNTER_VERSION=0       # CVE 总数量
  local lCVE_COUNTER_VERIFIED=0      # 已验证 CVE 数量（含专项模块验证结果）
  if [[ -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" ]]; then
    # 统计包含 "Exploit (" 字样的行数（即含利用代码的 CVE 条目）
    lEXPLOIT_COUNTER_VERSION=$(sort -u "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" | grep -c "Exploit (" || true)
    # 统计包含 CVE ID 格式的行数（即所有 CVE 条目）
    lCVE_COUNTER_VERSION=$(sort -u "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" | grep -c -E "CVE-[0-9]+-[0-9]+" || true)
    lCVE_COUNTER_VERIFIED="${lCVE_COUNTER_VERSION}"
  fi

  # -----------------------------------------------------------------------
  # Todo: 未来整合更多已验证漏洞来源
  #   * S26（Linux 内核漏洞验证）
  #   * S118（BusyBox 漏洞验证）
  # -----------------------------------------------------------------------

  # Linux 内核：查询 S26 模块的内核符号+配置验证结果，获取经过双重验证的 CVE 数量
  if [[ "${lPRODUCT_NAME}" == "linux_kernel" ]]; then
    local lKVERIFIED=0
    if [[ -f "${S26_LOG_DIR}/kernel_verification_${lVERS}_detailed.log" ]]; then
      # 统计包含 " verified - " 标记的行数（表示通过内核符号和配置验证的 CVE）
      lKVERIFIED=$(grep -c " verified - " "${S26_LOG_DIR}/kernel_verification_${lVERS}_detailed.log" || true)
    fi
    # 若有已验证的内核 CVE，在显示格式中附加已验证数量（括号中）
    if [[ "${lKVERIFIED}" -gt 0 ]]; then
      lCVE_COUNTER_VERIFIED="${lCVE_COUNTER_VERSION} (${lKVERIFIED})"
    fi
  fi

  # BusyBox：查询 S118 模块的 BusyBox applet 验证结果，获取已验证的 CVE 数量
  if [[ "${lPRODUCT_NAME}" == "busybox" ]]; then
    local lBB_VERIFIED=0
    if [[ -f "${S118_CSV_LOG}" ]]; then
      # 统计包含 busybox CVE 记录的行数
      lBB_VERIFIED=$(grep -c ":busybox:.*;CVE-" "${S118_CSV_LOG}" || true)
      if [[ "${lBB_VERIFIED}" -gt 0 ]]; then
        lCVE_COUNTER_VERIFIED="${lCVE_COUNTER_VERSION} (${lBB_VERIFIED})"
      fi
    fi
  fi

  # -----------------------------------------------------------------------
  # 根据是否有漏洞利用代码，选择不同颜色和格式输出漏洞汇总行
  # -----------------------------------------------------------------------
  if [[ "${lEXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    # 有可用利用代码（高危）：使用红色/粗体突出显示
    write_log "" "${lBIN_LOG}"
    # 将 CVE 详情追加到最终日志文件
    cat "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" >> "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
    write_log "[+] Identified ${RED}${BOLD}${lCVE_COUNTER_VERIFIED}${GREEN} CVEs and ${RED}${BOLD}${lEXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lPRODUCT_NAME}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"

    # 写入汇总表（品红色=有利用代码的高危组件）
    printf "[${MAGENTA}+${NC}]${MAGENTA} Component details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-20.20s${NC}\n" "${lPRODUCT_NAME}" "${lVERS}" "${lCVE_COUNTER_VERIFIED}" "${lEXPLOIT_COUNTER_VERSION}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  elif [[ "${lCVE_COUNTER_VERSION}" -gt 0 ]]; then
    # 有 CVE 但无利用代码（中危）：使用橙色显示
    write_log "" "${lBIN_LOG}"
    cat "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" >> "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
    write_log "[+] Identified ${ORANGE}${BOLD}${lCVE_COUNTER_VERIFIED}${GREEN} CVEs in ${ORANGE}${lPRODUCT_NAME}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"

    # 写入汇总表（橙色=有 CVE 但无利用代码的组件）
    printf "[${ORANGE}+${NC}]${ORANGE} Component details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-20.20s${NC}\n" "${lPRODUCT_NAME}" "${lVERS}" "${lCVE_COUNTER_VERIFIED}" "${lEXPLOIT_COUNTER_VERSION}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  else
    # 无 CVE（低危或安全）：使用绿色显示
    write_log "[+] Identified ${GREEN}${BOLD}${lCVE_COUNTER_VERIFIED:-0}${GREEN} CVEs in ${ORANGE}${lPRODUCT_NAME}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    printf "[${GREEN}+${NC}]${GREEN} Component details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-20.20s${NC}\n" "${lPRODUCT_NAME}" "${lVERS}" "${lCVE_COUNTER_VERIFIED:-0}" "${lEXPLOIT_COUNTER_VERSION:-0}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  fi
  # 写入分隔线，区分不同组件的报告块
  write_log "\\n-----------------------------------------------------------------\\n" "${lBIN_LOG}"

  # 清理临时 CVE 汇总文件（内容已合并到 _finished.txt 中，不再需要）
  if [[ -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" ]]; then
    rm "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPRODUCT_NAME}_${lVERS}.txt" || true
  fi

  # 将该组件的最终报告追加到模块主日志文件（使用 tee 同时写文件和标准输出）
  if [[ -f "${lBIN_LOG}" ]]; then
    tee -a "${LOG_FILE}" < "${lBIN_LOG}"
  fi
}

# ==========================================================================================
# tear_down_cve_threader - CVE 记录详细分析线程函数
#
# 功能：
#   对 cve-bin-tool 输出的单条 CVE 记录进行深度分析：
#   1. 黑白名单过滤（CVE_BLACKLIST / CVE_WHITELIST）
#   2. 查询 EPSS（漏洞利用预测评分）和 KEV（已知被利用漏洞）数据库
#   3. 查找可用的漏洞利用代码来源：
#      - Exploit-DB (EDB)          - exploit-db.com 上的 PoC
#      - Metasploit (MSF)          - Metasploit Framework 模块
#      - PacketStorm Security (PSS)- packetstormsecurity.com 上的 PoC
#      - Snyk                      - Snyk 漏洞数据库 PoC
#      - RouterSploit (RS)         - RouterSploit 漏洞利用框架
#      - linux-exploit-suggester   - 内核漏洞利用建议工具
#   4. 验证内核/BusyBox CVE 是否已由专项模块确认
#   5. 判断漏洞利用类型（本地 L / 远程 R / DoS D）
#   6. 按 CVSS 严重等级（CRITICAL/HIGH/MEDIUM/LOW）格式化输出
#   7. 生成标准 CycloneDX VEX JSON 条目（使用 jo 工具）
#
# 参数：
#   $1 - lCVE_LINE: 逗号分隔的 CVE 数据行，格式为：
#        BOM_REF,ORIG_SOURCE,VENDOR,PRODUCT,VERSION,CVE_ID,SEVERITY,SCORE,SOURCE,CVSS_VERS,CVSS_VECTOR
#
# 输出文件（示例）：
#   ${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt  - CVE 格式化输出
#   ${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.json - VEX JSON 条目
#   ${LOG_PATH_MODULE}/exploit/                                            - 利用代码副本目录
# ==========================================================================================
tear_down_cve_threader() {
  local lCVE_LINE="${1:-}"    # 输入的完整 CVE 数据行（逗号分隔）
  local lCVE_DATA_ARR=()      # 解析后的字段数组

  # 将逗号分隔的 CSV 行拆分为数组（每行一个字段）
  mapfile -t lCVE_DATA_ARR < <(echo "${lCVE_LINE}" | tr ',' '\n')

  # 按字段位置提取各数据项
  local lBOM_REF="${lCVE_DATA_ARR[*]:0:1}"        # 字段 0: BOM 引用 ID
  local lORIG_SOURCE="${lCVE_DATA_ARR[*]:1:1}"     # 字段 1: 来源标识

  # local lBIN_VENDOR="${lCVE_DATA_ARR[*]:2:1}"   # 字段 2: 二进制供应商（暂未使用）
  local lBIN_NAME="${lCVE_DATA_ARR[*]:3:1}"        # 字段 3: 产品/二进制名称
  local lBIN_VERS="${lCVE_DATA_ARR[*]:4:1}"        # 字段 4: 版本号
  local lCVE_ID="${lCVE_DATA_ARR[*]:5:1}"          # 字段 5: CVE 编号（如 CVE-2023-1234）
  local lCVSS_SEVERITY="${lCVE_DATA_ARR[*]:6:1}"   # 字段 6: CVSS 严重等级（CRITICAL/HIGH/MEDIUM/LOW）
  local lCVSS_SCORE="${lCVE_DATA_ARR[*]:7:1}"      # 字段 7: CVSS 评分（数值，如 9.8）
  local lVULN_SOURCE="${lCVE_DATA_ARR[*]:8:1}"     # 字段 8: 漏洞数据来源（如 NVD）
  local lCVSS_VERS="${lCVE_DATA_ARR[*]:9:1}"       # 字段 9: CVSS 版本（如 3.1）
  local lCVSS_VECTOR="${lCVE_DATA_ARR[*]:10:1}"    # 字段 10: CVSS 向量字符串（如 CVSS:3.1/AV:N/AC:L/...）

  # -----------------------------------------------------------------------
  # 黑名单检查：若 CVE 在黑名单文件中，跳过处理（用于屏蔽误报或已确认无关的 CVE）
  # -----------------------------------------------------------------------
  if [[ -f "${CVE_BLACKLIST}" ]]; then
    if grep -q ^"${lCVE_ID}"$ "${CVE_BLACKLIST}"; then
      print_output "[*] ${ORANGE}${lCVE_ID}${NC} for ${ORANGE}${lBIN_NAME}${NC} blacklisted and ignored." "no_log"
      return
    fi
  fi

  # -----------------------------------------------------------------------
  # 白名单检查：若白名单文件存在且包含有效条目，仅处理白名单中的 CVE
  # -----------------------------------------------------------------------
  if [[ -f "${CVE_WHITELIST}" ]]; then
    # 先检查白名单文件是否有实质内容（避免空白名单导致所有 CVE 被过滤）
    if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
      if ! grep -q ^"${lCVE_ID}"$ "${CVE_WHITELIST}"; then
        print_output "[*] ${ORANGE}${lCVE_ID}${NC} for ${ORANGE}${lBIN_NAME}${NC} not in whitelist -> ignored." "no_log"
        return
      fi
    fi
  fi

  # -----------------------------------------------------------------------
  # 初始化漏洞利用状态变量
  # -----------------------------------------------------------------------
  local lEXPLOIT="No exploit available"   # 利用代码描述字符串（初始值：无利用代码）
  local lKNOWN_EXPLOITED=0                # 是否在 KEV（已知被利用漏洞）数据库中（0=否，1=是）
  local lKERNEL_VERIFIED_VULN=0           # 已验证的内核 CVE 计数
  local lKERNEL_VERIFIED="no"             # 是否为已验证内核 CVE（"yes"/"no"）
  local lBUSYBOX_VERIFIED="no"            # 是否为已验证 BusyBox CVE（"yes"/"no"）
  local lEDB=0                            # 是否已找到任意利用代码（用于防止重复计数）
  local lKERNEL_CVE_EXPLOIT=""            # 当前比较的内核 CVE 利用条目

  local lEXPLOIT_AVAIL_EDB_ARR=()         # Exploit-DB 查找结果
  local lEXPLOIT_AVAIL_MSF_ARR=()         # Metasploit 查找结果
  local lEXPLOIT_MSF=""                   # 单条 Metasploit 利用模块记录
  local lEXPLOIT_PATH=""                  # 利用代码文件路径
  local lEXPLOIT_NAME=""                  # 利用代码名称（不含扩展名）
  local lEXPLOIT_AVAIL_PACKETSTORM_ARR=() # PacketStorm 查找结果
  local lEXPLOIT_AVAIL_SNYK_ARR=()        # Snyk 查找结果
  local lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR=() # RouterSploit CVE 数据库查找结果
  local lVEX_EXPLOIT_PROP_ARRAY_ARR=()    # VEX JSON 中利用代码属性数组
  local lEID_VALUE=""                     # EDB 利用 ID 临时变量
  local lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR=() # RouterSploit exploit-db 关联查找结果
  local lEXPLOIT_IDS_ARR=()               # EDB 利用 ID 数组（去重后）
  local lEXPLOIT_ID=""                    # 单个 EDB 利用 ID
  local lLOCAL=0                          # 是否已标记本地漏洞利用类型（防重复标记）
  local lREMOTE=0                         # 是否已标记远程漏洞利用类型（防重复标记）
  local lDOS=0                            # 是否已标记 DoS 漏洞利用类型（防重复标记）
  local lEXPLOIT_ENTRY=""                 # 遍历利用条目时的临时变量
  local lE_FILE=""                        # 利用代码文件路径（从 EDB 条目中提取）
  local lEXPLOIT_SNYK=""                  # 单条 Snyk 利用记录
  local lEXPLOIT_PS=""                    # 单条 PacketStorm 利用记录
  local lEXPLOIT_RS=""                    # 单条 RouterSploit 利用记录
  local lPS_TYPE=""                       # PacketStorm 利用类型（remote/local/DoS）
  local lFIRST_EPSS=0                     # EPSS 评分（漏洞利用预测概率百分比）

  # -----------------------------------------------------------------------
  # 根据 CVSS 向量判断漏洞利用类型
  #   AV:L = 本地利用 (Local)
  #   AV:N = 远程利用 (Network/Remote)
  #   其他或未知 = NA
  # -----------------------------------------------------------------------
  local lTYPE="NA"
  if [[ "${lCVSS_VECTOR}" == *"AV:L"* ]]; then
    lTYPE="L"
  elif [[ "${lCVSS_VECTOR}" == *"AV:N"* ]]; then
    lTYPE="R"
  fi

  # -----------------------------------------------------------------------
  # VEX 指标收集（仅在 VEX_METRICS=1 时执行）
  # -----------------------------------------------------------------------
  if [[ "${VEX_METRICS}" -eq 1 ]]; then
    # 查询 EPSS 数据（格式：EPSS分数;百分比）
    lFIRST_EPSS=$(get_epss_data "${lCVE_ID}")
    # 从返回值中提取 EPSS 评分部分（分号前的部分）
    lFIRST_EPSS="${lFIRST_EPSS/\;*}"

    # -------------------------------------------------------------------
    # 检查 KEV（Known Exploited Vulnerabilities）数据库
    # CISA 维护的已知被实际利用漏洞列表
    # -------------------------------------------------------------------
    if grep -q "^${lCVE_ID}," "${KNOWN_EXP_CSV}"; then
      # 写入 KEV 发现记录
      write_log "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a known exploited vulnerability.${NC}" "${LOG_PATH_MODULE}/KEV.txt"

      # 更新利用代码描述字符串
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (KEV"
      else
        lEXPLOIT+=" / KEV"
      fi
      # 附加利用类型标记
      if [[ "${lTYPE}" != "NA" ]]; then
        lEXPLOIT+=" (${lTYPE})"
      fi
      lKNOWN_EXPLOITED=1
      lEDB=1  # 标记已找到利用代码（防止重复计数）
    fi

    # -------------------------------------------------------------------
    # linux-exploit-suggester 内核漏洞利用检查
    # 在 S25 模块收集的内核漏洞利用列表中搜索当前 CVE
    # -------------------------------------------------------------------
    if [[ "${lBIN_NAME}" == *kernel* ]]; then
      for lKERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS_ARR[@]}"; do
        # 提取利用条目中的 CVE ID（第3个分号分隔字段）
        lKERNEL_CVE_EXPLOIT=$(echo "${lKERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
        if [[ "${lKERNEL_CVE_EXPLOIT}" == "${lCVE_ID}" ]]; then
          lEXPLOIT="Exploit (linux-exploit-suggester"
          if [[ "${lTYPE}" != "NA" ]]; then
            lEXPLOIT+=" (${lTYPE})"
          fi
          # 写入内核漏洞利用计数临时文件
          write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};kernel exploit" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
          lEDB=1
        fi
      done

      # 检查 S26 模块（内核漏洞验证）的 CSV 结果文件
      if [[ -f "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv ]]; then
        # 格式：...;CVE_ID;...;...;kernel_symbols_match(1/0);kernel_config_match(1/0)
        # 同时通过内核符号验证和内核配置验证（最高置信度）
        if grep -q ";${lCVE_ID};.*;.*;1;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
          print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols and kernel configuration${GREEN})!" "no_log"
          ((lKERNEL_VERIFIED_VULN+=1))
          lKERNEL_VERIFIED="yes"
        fi
        # 仅通过内核符号验证（中等置信度）
        if grep -q ";${lCVE_ID};.*;.*;1;0" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
          print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols${GREEN})!" "no_log"
          ((lKERNEL_VERIFIED_VULN+=1))
          lKERNEL_VERIFIED="yes"
        fi
        # 仅通过内核配置验证（较低置信度）
        if grep -q ";${lCVE_ID};.*;.*;0;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
          print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel configuration${GREEN})!" "no_log"
          ((lKERNEL_VERIFIED_VULN+=1))
          lKERNEL_VERIFIED="yes"
        fi
      fi
    fi

    # -------------------------------------------------------------------
    # BusyBox CVE 验证检查（S118 模块）
    # 检查该 CVE 是否经 S118 BusyBox 验证器确认影响实际的 BusyBox applet
    # -------------------------------------------------------------------
    if [[ -f "${CSV_DIR}"/s118_busybox_verifier.csv ]] && [[ "${lBIN_NAME}" == *"busybox"* ]]; then
      if grep -q ";${lCVE_ID};" "${CSV_DIR}"/s118_busybox_verifier.csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified BusyBox vulnerability (${ORANGE}BusyBox applet${GREEN})!" "no_log"
        lBUSYBOX_VERIFIED="yes"
      fi
    fi

    # -------------------------------------------------------------------
    # 查找可用的漏洞利用代码
    # -------------------------------------------------------------------

    # Exploit-DB 查找（cve_searchsploit 是 EMBA 封装的搜索函数）
    mapfile -t lEXPLOIT_AVAIL_EDB_ARR < <(cve_searchsploit "${lCVE_ID}" 2>/dev/null || true)
    # Metasploit Framework 查找（在本地 MSF 数据库文件中搜索）
    mapfile -t lEXPLOIT_AVAIL_MSF_ARR < <(grep -E "${lCVE_ID}"$ "${MSF_DB_PATH}" 2>/dev/null || true)
    # PacketStorm Security 查找（在本地 PS_PoC_results.csv 中搜索）
    mapfile -t lEXPLOIT_AVAIL_PACKETSTORM_ARR < <(grep -E "^${lCVE_ID}\;" "${CONFIG_DIR}"/PS_PoC_results.csv 2>/dev/null || true)
    # Snyk 漏洞数据库查找（在本地 Snyk_PoC_results.csv 中搜索）
    mapfile -t lEXPLOIT_AVAIL_SNYK_ARR < <(grep -E "^${lCVE_ID}\;" "${CONFIG_DIR}"/Snyk_PoC_results.csv 2>/dev/null || true)
    # RouterSploit CVE 数据库查找（在 routersploit_cve-db.txt 中搜索）
    mapfile -t lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR < <(grep -E "${lCVE_ID}"$ "${CONFIG_DIR}/routersploit_cve-db.txt" 2>/dev/null || true)

    # -------------------------------------------------------------------
    # 处理 Exploit-DB 查找结果
    # -------------------------------------------------------------------
    if [[ " ${lEXPLOIT_AVAIL_EDB_ARR[*]} " =~ "Exploit DB Id:" ]]; then
      # 对 EDB 结果中的每个 ID，尝试在 RouterSploit exploit-db 映射表中查找关联模块
      for lEID_VALUE in "${EXPLOIT_AVAIL_EDB_ARR[@]}"; do
        if ! echo "${lEID_VALUE}" | grep -q "Exploit DB Id:"; then
          continue
        fi
        lEID_VALUE=$(echo "${lEID_VALUE}" | grep "Exploit DB Id:" | cut -d: -f2)
        mapfile -t lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR < <(grep "${lEID_VALUE}" "${CONFIG_DIR}/routersploit_exploit-db.txt" 2>/dev/null || true)
      done

      # 提取所有 EDB 利用 ID（去重、纯数字）
      readarray -t lEXPLOIT_IDS_ARR < <(echo "${lEXPLOIT_AVAIL_EDB_ARR[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //' | sort -u)

      # 更新利用代码描述字符串（追加 EDB ID）
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (EDB ID:"
      else
        lEXPLOIT+=" / EDB ID:"
      fi

      for lEXPLOIT_ID in "${lEXPLOIT_IDS_ARR[@]}" ; do
        # 记录到 VEX 属性数组
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:EDB:${lEXPLOIT_ID}" )
        lEXPLOIT+=" ${lEXPLOIT_ID}"
        # 写入利用代码说明文件
        write_log "[+] Exploit for ${lCVE_ID}:\\n" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
        write_log "[+] EDB Exploit for ${lCVE_ID} identified"  "${LOG_PATH_MODULE}/exploit/EDB_${lEXPLOIT_ID}_notes.txt"
        write_log "${lEXPLOIT_AVAIL_EDB_ARR[*]/\ /\\n}" "${LOG_PATH_MODULE}/exploit/edb_${lEXPLOIT_ID}_notes.txt"

        # 根据利用类型标记 L（本地）、R（远程）或 D（DoS）
        if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: local" && "${lLOCAL:-0}" -eq 0 ]]; then
          lEXPLOIT+=" (L)"
          lLOCAL=1
        fi
        if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: remote" && "${lREMOTE:-0}" -eq 0 ]]; then
          lEXPLOIT+=" (R)"
          lREMOTE=1
        fi
        if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: dos" && "${lDOS:-0}" -eq 0 ]]; then
          lEXPLOIT+=" (D)"
          lDOS=1
        fi
        lEDB=1
        # 写入利用代码计数临时文件（后续用于统计）
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};exploit_db" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
      done

      # 将 EDB 利用代码文件复制到报告的 exploit/ 目录，供 HTML 报告引用
      for lEXPLOIT_ENTRY in "${lEXPLOIT_AVAIL_EDB_ARR[@]}"; do
        if [[ "${lEXPLOIT_ENTRY}" =~ "File:" ]]; then
          lE_FILE=$(echo "${lEXPLOIT_ENTRY}" | awk '{print $2}')
          if [[ -f "${lE_FILE}" ]] ; then
            cp "${lE_FILE}" "${LOG_PATH_MODULE}""/exploit/edb_""$(basename "${lE_FILE}")" || print_error "[-] Copy exploit error for ${lE_FILE}"
          fi
        fi
      done
    fi

    # -------------------------------------------------------------------
    # 处理 Metasploit 查找结果
    # -------------------------------------------------------------------
    if [[ ${#lEXPLOIT_AVAIL_MSF_ARR[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (MSF:"
      else
        lEXPLOIT+=" / MSF:"
      fi

      for lEXPLOIT_MSF in "${lEXPLOIT_AVAIL_MSF_ARR[@]}" ; do
        # 构造 Metasploit 模块的完整路径（区分是否安装了 MSF）
        if ! [[ -d "${MSF_INSTALL_PATH}" ]]; then
          lEXPLOIT_PATH=$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
        else
          lEXPLOIT_PATH="${MSF_INSTALL_PATH}"$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
        fi
        lEXPLOIT_NAME=$(basename -s .rb "${lEXPLOIT_PATH}")  # 去掉 .rb 扩展名
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:MSF:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        if [[ -f "${lEXPLOIT_PATH}" ]] ; then
          # 将 MSF 模块复制到报告的 exploit/ 目录
          cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/msf_""${lEXPLOIT_NAME}".rb
          # 通过检查模块继承类型判断利用类型
          if grep -q "< Msf::Exploit::Remote" "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (R)"   # 远程利用模块
          fi
          if grep -q "< Msf::Exploit::Local" "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (L)"   # 本地提权模块
          fi
          if grep -q "include Msf::Auxiliary::Dos" "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (D)"   # DoS 辅助模块
          fi
        fi
      done

      # 仅在未找到其他利用代码时才计数（避免同一 CVE 被多个来源重复计数）
      if [[ ${lEDB} -eq 0 ]]; then
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};MSF" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    # -------------------------------------------------------------------
    # 处理 Snyk 查找结果
    # -------------------------------------------------------------------
    if [[ ${#lEXPLOIT_AVAIL_SNYK_ARR[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (Snyk:"
      else
        lEXPLOIT+=" / Snyk:"
      fi

      for lEXPLOIT_SNYK in "${lEXPLOIT_AVAIL_SNYK_ARR[@]}" ; do
        lEXPLOIT_NAME=$(echo "${lEXPLOIT_SNYK}" | cut -d\; -f2)  # 提取 Snyk 漏洞 ID（第2字段）
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:SNYK:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        # 附加利用类型标记
        if [[ "${lTYPE}" != "NA" ]]; then
          lEXPLOIT+=" (${lTYPE})"
        fi
      done

      # 仅在未找到其他利用代码时才计数
      if [[ ${lEDB} -eq 0 ]]; then
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};SNYK" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    # -------------------------------------------------------------------
    # 处理 PacketStorm Security 查找结果
    # -------------------------------------------------------------------
    if [[ ${#lEXPLOIT_AVAIL_PACKETSTORM_ARR[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (PSS:"
      else
        lEXPLOIT+=" / PSS:"
      fi

      for lEXPLOIT_PS in "${lEXPLOIT_AVAIL_PACKETSTORM_ARR[@]}" ; do
        # 从 URL 中提取最后两段路径作为利用名称（如 2023/exploit.tar.gz）
        lEXPLOIT_NAME=$(echo "${lEXPLOIT_PS}" | cut -d\; -f3 | rev | cut -d '/' -f1-2 | rev)
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:PSS:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        # 从 PS_PoC_results.csv 中查询该利用的类型（remote/local/DoS）
        lPS_TYPE=$(grep "^${lCVE_ID};" "${CONFIG_DIR}"/PS_PoC_results.csv | grep "${lEXPLOIT_NAME}" | cut -d\; -f4 || true)
        # 将字符串类型转换为简写字母
        if [[ "${lPS_TYPE}" == "remote" ]]; then
          lPS_TYPE="R"
        elif [[ "${lPS_TYPE}" == "local" ]]; then
          lPS_TYPE="L"
        elif [[ "${lPS_TYPE}" == "DoS" ]]; then
          lPS_TYPE="D"
        else
          # 若 PS 中没有类型信息，回退到 CVSS 向量推断的类型
          if [[ "${lTYPE}" != "NA" ]]; then
            lPS_TYPE="${lTYPE}"
          fi
        fi
        lEXPLOIT+=" (${lPS_TYPE})"
      done

      # 仅在未找到其他利用代码时才计数
      if [[ ${lEDB} -eq 0 ]]; then
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};PSS" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    # -------------------------------------------------------------------
    # 处理 RouterSploit 查找结果（来自两个来源：CVE 数据库和 EDB 关联）
    # -------------------------------------------------------------------
    if [[ "${#lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR[@]}" -gt 0 || "${#lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR[@]}" -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (Routersploit:"
      else
        lEXPLOIT+=" / Routersploit:"
      fi
      # 合并两个 RouterSploit 结果数组
      local lEXPLOIT_ROUTERSPLOIT_ARR=("${lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR[@]}" "${lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR[@]}")

      for lEXPLOIT_RS in "${lEXPLOIT_ROUTERSPLOIT_ARR[@]}" ; do
        lEXPLOIT_PATH=$(echo "${lEXPLOIT_RS}" | cut -d: -f1)
        lEXPLOIT_NAME=$(basename -s .py "${lEXPLOIT_PATH}")  # 去掉 .py 扩展名
        lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:RS:${lEXPLOIT_NAME}" )
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        if [[ -f "${lEXPLOIT_PATH}" ]] ; then
          # 将 RouterSploit 模块复制到报告目录
          cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/routersploit_""${lEXPLOIT_NAME}".py
          # 通过检查模块是否包含 Port 关键字来判断是否为远程利用
          if grep -q Port "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (R)"   # 有端口参数，属于远程利用
          else
            # 无端口信息时回退到 CVSS 类型
            if [[ "${lTYPE}" != "NA" ]]; then
              lEXPLOIT+=" (${lTYPE})"
            fi
          fi
        fi
      done

      # 仅在未找到其他利用代码时才计数
      if [[ ${lEDB} -eq 0 ]]; then
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};RS" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    # 为利用代码描述字符串添加结尾括号（对应各个 "Exploit (" 开头）
    if [[ ${lEDB} -eq 1 ]]; then
      lEXPLOIT+=")"
    fi

    # 若 CVE 已被专项模块验证，在 CVE ID 后追加 "(V)" 标记以便区分
    if [[ "${lKERNEL_VERIFIED}" == "yes" ]]; then lCVE_ID+=" (V)"; fi
    if [[ "${lBUSYBOX_VERIFIED}" == "yes" ]]; then lCVE_ID+=" (V)"; fi
  fi

  # 格式化 CVSS 评分字符串（含版本信息），如 "9.8 (v3.1)"
  lCVSS_SCORE_VERS="${lCVSS_SCORE} (v${lCVSS_VERS})"

  # -----------------------------------------------------------------------
  # 按 CVSS 严重等级格式化输出 CVE 详情
  # 颜色规则：
  #   CRITICAL + 有利用 → 品红色（最高警示）
  #   CRITICAL + 无利用 → 红色
  #   HIGH + 有利用     → 品红色
  #   HIGH + 无利用     → 红色
  #   MEDIUM + 有利用   → 品红色
  #   MEDIUM + 无利用   → 橙色
  #   LOW（其他）+ 有利用→ 品红色
  #   LOW（其他）+ 无利用→ 绿色
  # -----------------------------------------------------------------------
  # 若该组件的 CVE 汇总文件尚不存在，先写入表头
  if [[ ! -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt" ]]; then
    printf "${GREEN}\t%-20.20s:   %-12.12s:   %-20.20s:  %-10.10s : %-4.4s :   %-15.15s:   %s${NC}\n" "BIN NAME" "BIN VERS" "CVE ID" "CVSS VALUE" "EPSS" "SOURCE" "EXPLOIT" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
  fi

  if [[ "${lCVSS_SEVERITY}" == "CRITICAL" ]]; then
    # CRITICAL 级别 CVE
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      # 有利用代码：品红色（最高优先级警告）
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp  # 记录到全局严重等级统计
    else
      # 无利用代码：红色
      printf "${RED}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  elif [[ "${lCVSS_SEVERITY}" == "HIGH" ]]; then
    # HIGH 级别 CVE
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      printf "${RED}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  elif [[ "${lCVSS_SEVERITY}" == "MEDIUM" ]]; then
    # MEDIUM 级别 CVE
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      # 无利用代码的 MEDIUM CVE 使用橙色（区别于 HIGH/CRITICAL 的红色）
      printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  else
    # LOW 及其他等级 CVE
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
      echo "${lCVSS_SEVERITY}" >> "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp
    else
      # 低危且无利用代码：绿色
      printf "${GREEN}\t%-20.20s:   %-12.12s:   %-20.20s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID}" "${lCVSS_SCORE_VERS}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  fi

  # -----------------------------------------------------------------------
  # 生成 CycloneDX VEX JSON 条目
  #
  # 从 NVD JSON 数据集中提取该 CVE 的 CWE 分类和描述信息，
  # 然后使用 jo 工具构建符合 CycloneDX 1.5 VEX 标准的 JSON 对象
  #
  # NVD JSON 文件路径格式：
  #   ${NVD_DIR}/CVE-YYYY/CVE-YYYY-XXxx/CVE-YYYY-XXXXX.json
  # -----------------------------------------------------------------------

  # 从 NVD JSON 中提取 CWE 编号列表（去重，仅保留数字部分）
  mapfile -t lCWE < <(grep -o -E "CWE-[0-9]+" "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null | sort -u | cut -d '-' -f2|| true)
  # 从 NVD JSON 中提取英文描述
  lCVE_DESC=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null || true)

  # 生成唯一的漏洞 BOM 引用 ID（使用 UUID）
  local lVULN_BOM_REF=""
  lVULN_BOM_REF=$(uuidgen)
  # 构建 VEX 利用代码属性 JSON 数组（全局变量 PROPERTIES_JSON_ARR）
  build_sbom_json_properties_arr "${lVEX_EXPLOIT_PROP_ARRAY_ARR[@]}"

  # 确定漏洞详情 URL（目前仅支持 NVD 来源）
  # Todo: 未来支持更多动态 URL 来源
  if [[ "${lVULN_SOURCE}" == "NVD" ]]; then
    local lVULN_URL="https://nvd.nist.gov/vuln/detail/${lCVE_ID}"
  else
    local lVULN_URL="UNKNOWN"
  fi

  # 将 CVSS 评分四舍五入到 1 位小数（确保 JSON 中的数值格式干净）
  if [[ "${lCVSS_SCORE}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    lCVSS_SCORE=$(printf "%.${2:-1}f" "${lCVSS_SCORE}")
  else
    # 处理非数字的异常评分值，默认设为 0
    lCVSS_SCORE=0
  fi

  # -----------------------------------------------------------------------
  # 使用 jo 工具生成 CycloneDX VEX JSON 条目
  # 字段说明：
  #   bom-ref     - 本漏洞条目的唯一引用 ID（UUID）
  #   id          - CVE 编号（可能含 "(V)" 验证标记）
  #   source      - 漏洞数据来源（名称 + URL）
  #   ratings     - CVSS 评分数组（含评分、严重等级、CVSS 版本、向量）
  #   cwes        - CWE 分类编号数组
  #   analysis    - 分析状态（默认 in_triage，表示待进一步分析）
  #   description - CVE 英文描述（来自 NVD）
  #   affects     - 受影响组件（通过 BOM 引用关联到 SBOM 中的组件）
  #   properties  - 利用代码元数据（来源、类型、ID 等）
  # -----------------------------------------------------------------------
  jo -p -n -- \
    bom-ref="${lVULN_BOM_REF}" \
    id="${lCVE_ID}" \
    source="$(jo -n name="${lVULN_SOURCE}" url="${lVULN_URL}")" \
    ratings="$(jo -a "$(jo -n score="${lCVSS_SCORE}" severity="${lCVSS_SEVERITY,,}" method="CVSSv${lCVSS_VERS}" vector="${lCVSS_VECTOR}")")" \
    cwes="$(jo -a "${lCWE[@]:-null}")" \
    analysis="$(jo -n state="in_triage")" \
    description="${lCVE_DESC}" \
    affects="$(jo -a "$(jo -n ref="${lBOM_REF}" versions="$(jo -a "$(jo -n -- -s component="${lPRODUCT_NAME}" -s version="${lVERS}")")")")" \
    properties="$(jo -a "${PROPERTIES_JSON_ARR[@]:-null}")" \
    > "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.tmp.json" || print_error "[*] VEX entry failed for ${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lEXPLOIT}"

  # 使用 jq 格式化 JSON（美化输出，便于人工审阅）
  jq . "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.tmp.json" > "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.json"

  # 删除临时的 jo 原始输出文件
  rm "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPRODUCT_NAME}_${lVERS}.tmp.json" || true
}

# ==========================================================================================
# get_kernel_s25_data - 从 S25 模块日志加载内核 CVE 利用数据
#
# 功能：
#   读取 S25（linux-exploit-suggester 集成）模块生成的 CSV 日志，
#   将内核已知 CVE 利用条目加载到全局数组 KERNEL_CVE_EXPLOITS_ARR 中。
#   该数组后续被 tear_down_cve_threader 用于检查某个内核 CVE 是否有
#   linux-exploit-suggester 确认的利用代码。
#
# 全局变量：
#   输出：KERNEL_CVE_EXPLOITS_ARR - 格式：":linux:linux_kernel;VERSION;CVE-XXXX-XXXX"
#
# 依赖：
#   S25_LOG - S25 模块 CSV 日志文件路径（全局变量）
# ==========================================================================================
get_kernel_s25_data() {
  export KERNEL_CVE_EXPLOITS_ARR=()

  if [[ -f "${S25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S25_LOG}")."
    # 读取 S25 日志（跳过标题行），提取前3列（CPE;版本;CVE），去重
    readarray -t KERNEL_CVE_EXPLOITS_ARR < <(cut -d\; -f1-3 "${S25_LOG}" | tail -n +2 | sort -u || true)
    # 结果格式示例：":linux:linux_kernel;5.10.59;CVE-2021-3490"
  fi
}

# ==========================================================================================
# get_epss_data - 查询 CVE 的 EPSS（漏洞利用预测评分系统）数据
#
# 功能：
#   从本地 EPSS 数据文件中查询指定 CVE 的 EPSS 评分和百分位数。
#   EPSS（Exploit Prediction Scoring System）是一个预测漏洞在未来
#   30 天内被实际利用的概率模型，由 FIRST.org 维护。
#
# 参数：
#   $1 - lCVE_ID: CVE 编号（如 CVE-2023-1234）
#
# 返回值（通过 echo 输出）：
#   格式：EPSS分数(×100取整);百分位数(×100取整)
#   示例：12;45 表示 EPSS 分数 12%，位于第 45 百分位
#   若数据不存在，对应字段返回 "NA"
#
# 依赖：
#   EPSS_DATA_PATH - 本地 EPSS CSV 数据目录（全局变量）
#   文件命名格式：CVE_YYYY_EPSS.csv
#   文件字段格式：CVE_ID;EPSS_SCORE;PERCENTILE
# ==========================================================================================
get_epss_data() {
  local lCVE_ID="${1:-}"      # 待查询的 CVE 编号
  local lCVE_EPSS_PATH=""     # EPSS 数据文件路径
  local lEPSS_PERC=""         # EPSS 百分位数（原始值）
  local lEPSS_EPSS=""         # EPSS 评分（原始值）
  local lEPSS_DATA=""         # 查询到的原始 CSV 行
  local lCVE_YEAR=""          # CVE 编号中的年份（用于定位对应年份的数据文件）

  # 从 CVE ID 中提取年份（格式：CVE-YYYY-NNNNN，取第2段）
  lCVE_YEAR="$(echo "${lCVE_ID}" | cut -d '-' -f2)"
  # 构造对应年份的 EPSS 数据文件路径
  lCVE_EPSS_PATH="${EPSS_DATA_PATH}/CVE_${lCVE_YEAR}_EPSS.csv"

  if [[ -f "${lCVE_EPSS_PATH}" ]]; then
    # 在 EPSS 数据文件中搜索该 CVE 的记录（精确匹配行首）
    lEPSS_DATA=$(grep "^${lCVE_ID};" "${lCVE_EPSS_PATH}" || true)
    # 提取第3列（百分位数）并乘以 100 取整（转为百分比整数）
    lEPSS_PERC=$(echo "${lEPSS_DATA}" | cut -d ';' -f3)
    lEPSS_PERC=$(echo "${lEPSS_PERC} 100" | awk '{printf "%d", $1 * $2}')
    # 提取第2列（EPSS 评分）并乘以 100 取整（转为百分比整数）
    lEPSS_EPSS=$(echo "${lEPSS_DATA}" | cut -d ';' -f2)
    lEPSS_EPSS=$(echo "${lEPSS_EPSS} 100" | awk '{printf "%d", $1 * $2}')
  fi

  # 若结果不是整数，返回 "NA"（表示数据不可用）
  [[ ! "${lEPSS_EPSS}" =~ ^[0-9]+$ ]] && lEPSS_EPSS="NA"
  [[ ! "${lEPSS_PERC}" =~ ^[0-9]+$ ]] && lEPSS_PERC="NA"

  # 以 "EPSS评分;百分位数" 格式输出结果
  echo "${lEPSS_EPSS};${lEPSS_PERC}"
}

# ==========================================================================================
# backup_vex_file - 备份已有 VEX 文件（重新扫描模式使用）
#
# 功能：
#   在重新扫描（RESCAN_SBOM=1）时，将已有的 VEX JSON 文件进行备份，
#   以保留历史版本，同时为新生成的文件腾出标准路径。
#
#   备份策略：
#   1. 首先将已有的 <name>.previous.json 重命名为 <name>.previous_N.json
#      （N 从 1 开始，自动寻找未使用的序号）
#   2. 然后将当前文件重命名为 <name>.previous.json
#
#   示例（第2次重新扫描后）：
#     EMBA_sbom_vex_only.previous_1.json  ← 第1次扫描生成
#     EMBA_sbom_vex_only.previous.json    ← 第2次（最近一次）扫描前的版本
#
# 参数：
#   $1 - lFILE_PATH: 要备份的文件完整路径
# ==========================================================================================
backup_vex_file() {
  local lFILE_PATH="${1:-}"   # 待备份的文件路径

  if [[ -f "${lFILE_PATH}" ]]; then
    local lCOUNTER=1
    local lBASE_NAME="${lFILE_PATH%%.json}"  # 去掉 .json 扩展名，获取基础文件名

    # 寻找下一个未使用的备份序号（从 1 开始递增）
    while [[ -f "${lBASE_NAME}.previous_${lCOUNTER}.json" ]]; do
      ((lCOUNTER++))
    done

    # 若已存在 .previous.json，将其归档为带序号的版本
    if [[ -f "${lBASE_NAME}.previous.json" ]]; then
      mv "${lBASE_NAME}.previous.json" "${lBASE_NAME}.previous_${lCOUNTER}.json"
    fi

    # 将当前文件重命名为 .previous.json
    mv "${lFILE_PATH}" "${lBASE_NAME}.previous.json"
    print_output "[*] Backed up ${lFILE_PATH} as $(basename "${lBASE_NAME}.previous.json")" "no_log"
  fi
}
