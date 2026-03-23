#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# ==========================================================================================
# 模块名称: S26_kernel_vuln_verifier (内核漏洞验证器)
#
# 功能描述:
#   在S24模块成功识别Linux内核后,本模块执行以下任务:
#   1. 等待内核源码下载完成(kernel_downloader)
#   2. 从S24的CSV日志中提取内核版本信息
#   3. 使用cve-bin-tool基于版本号识别CVE漏洞
#   4. 提取内核符号用于验证漏洞
#   5. 尝试编译内核以验证受影响的源文件
#   6. 通过符号匹配和编译验证来确认漏洞的真实性
#   7. 生成最终漏洞报告
#
# 验证机制:
#   - 符号验证: 检查CVE中提到的源文件是否使用了内核导出的符号
#   - 编译验证: 检查CVE中提到的源文件是否在实际编译中被使用
#
# 依赖模块/工具:
#   - S24_kernel_bin_identifier: 内核识别模块
#   - kernel_downloader: 内核源码下载器
#   - cve-bin-tool: CVE漏洞数据库工具
#   - readelf: ELF文件分析
#   - NVD CVE数据库
#
# 输入:
#   - S24_CSV_LOG: S24模块生成的内核信息CSV
#   - 内核源码包: ${EXT_DIR}/linux_kernel_sources/linux-${版本}.tar.gz
#   - CVE数据库: ${NVD_DIR}
#
# 输出:
#   - 漏洞验证CSV结果
#   - 符号验证结果文件
#   - 编译验证结果文件
#   - 最终漏洞报告
# ==========================================================================================

# 设置线程优先级为1(低优先级)
export THREAD_PRIO=1

# ==========================================================================================
# S26_kernel_vuln_verifier - 内核漏洞验证主函数
#
# 工作流程:
#   1. 初始化模块日志
#   2. 检查内核源码目录是否存在
#   3. 等待S24模块完成
#   4. 从S24的CSV日志提取内核版本
#   5. 对每个内核版本执行漏洞验证:
#      - 查找内核ELF文件和配置文件
#      - 等待并验证内核源码下载
#      - 使用cve-bin-tool检测CVE
#      - 提取内核符号
#      - 编译内核(dry-run)获取使用的源文件
#      - 并行验证每个CVE
#   6. 汇总并输出最终报告
# ==========================================================================================
S26_kernel_vuln_verifier()
{
  # 初始化模块日志系统
  module_log_init "${FUNCNAME[0]}"
  # 显示模块标题
  module_title "Kernel vulnerability identification and verification"
  # 预报告模块状态
  pre_module_reporter "${FUNCNAME[0]}"

  # 保存当前工作目录
  export HOME_DIR=""
  HOME_DIR="$(pwd)"
  # lKERNEL_ARCH_PATH是存储所有内核源码的目录
  local lKERNEL_ARCH_PATH="${EXT_DIR}""/linux_kernel_sources"
  local lWAIT_PIDS_S26_ARR=()

  # 检查内核源码目录是否存在
  if ! [[ -d "${lKERNEL_ARCH_PATH}" ]]; then
    print_output "[-] Missing directory for kernel sources ... exit module now"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # 等待S24模块完成,以获取内核版本信息
  # we wait until the s24 module is finished and hopefully shows us a kernel version
  module_wait "S24_kernel_bin_identifier"

  # 现在应该有包含内核版本的CSV日志了:
  # shellcheck disable=SC2153
  if ! [[ -f "${S24_CSV_LOG}" ]] || [[ "$(wc -l < "${S24_CSV_LOG}")" -lt 1 ]]; then
    print_output "[-] No Kernel version file (s24 results) identified ..."
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # 从S24的CSV日志中提取内核版本
  # extract kernel version
  get_kernel_version_csv_data_s24 "${S24_CSV_LOG}"

  # 局部变量声明
  local lKERNEL_DATA=""                 # 内核数据条目
  local lKERNEL_ELF_EMBA_ARR=()        # 内核ELF文件数组
  local lALL_KVULNS_ARR=()             # 所有内核漏洞数组
  export KERNEL_CONFIG_PATH="NA"       # 内核配置文件路径
  export KERNEL_ELF_PATH=""             # 内核ELF文件路径
  local lK_VERSION_KORG=""              # 原始内核版本
  export COMPILE_SOURCE_FILES_VERIFIED=0  # 已验证的编译源文件数
  local lK_VERSION=""                   # 当前处理的内核版本

  # 遍历从S24获取的所有内核版本
  # K_VERSIONS_ARR is from get_kernel_version_csv_data_s24
  for lK_VERSION in "${K_VERSIONS_ARR[@]}"; do
    export VULN_CNT=1                   # 漏洞计数器
    # 跳过无效版本(单字符版本号)
    [[ "${lK_VERSION}" =~ ^[0-9\.a-zA-Z]$ ]] && continue

    local lK_FOUND=0                     # 标记是否找到有效内核信息
    print_output "[+] Identified kernel version: ${ORANGE}${lK_VERSION}${NC}"

    # 从S24的CSV中查找匹配当前版本的条目
    # 按第4列(版本号)倒序排列,优先处理高版本
    mapfile -t lKERNEL_ELF_EMBA_ARR < <(grep "${lK_VERSION}" "${S24_CSV_LOG}" | \
      grep -v "config extracted" | sort -u | sort -r -n -t\; -k4 || true)

    # ============================================================
    # 步骤1: 尝试找到内核配置文件和对应的ELF文件
    # 优先级:
    #   1. 有配置文件 + 有ELF文件
    #   2. 有ELF文件 + 有init参数
    #   3. 只有ELF文件
    # ============================================================
    # we check for a kernel configuration
    for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
      # print_output "[*] KERNEL_DATA: ${lKERNEL_DATA}" "no_log"
      # 第5字段是内核配置文件路径
      if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f5)" == "/"* ]]; then
        # field 5 is the kernel config file
        KERNEL_CONFIG_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f5)
        print_output "[+] Found kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        # 使用第一个检测到内核配置的条目
        # we use the first entry with a kernel config detected
        # 第1字段是匹配的kernel elf文件 - 有时只有配置没有elf文件
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # field 1 is the matching kernel elf file - sometimes we have a config but no elf file
          KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
          print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
          lK_FOUND=1
          break
        fi
      fi
    done

    # 如果没找到,尝试找有init条目的ELF文件
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      print_output "[-] No kernel configuration file with matching elf file found for kernel ${ORANGE}${lK_VERSION}${NC}."
    fi

    # 尝试查找有init参数的内核
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
        # check for some path indicator for the elf file
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # now we check for init entries
          if ! [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f2)" == "NA" ]]; then
            KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
            # we use the first entry with a kernel init detected
            print_output "[+] Found kernel elf file with init entry: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
            lK_FOUND=1
            break
          fi
        fi
      done
    fi

    # 最后手段: 使用第一个有效的ELF文件
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
        # check for some path indicator for the elf file
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # this means we have no kernel configuration found
          # and no init entry -> we just use the first valid elf file
          if ! [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "NA" ]]; then
            KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
            print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
            # we use the first entry as final resort
            lK_FOUND=1
            break
          fi
        fi
      done
    end

    # 检查用户是否提供了内核配置文件
    if [[ -f "${KERNEL_CONFIG}" ]]; then
      # check if the provided configuration is for the kernel version under test
      if grep -q "${lK_VERSION}" "${KERNEL_CONFIG}"; then
        KERNEL_CONFIG_PATH="${KERNEL_CONFIG}"
        print_output "[+] Using provided kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        lK_FOUND=1
      fi
    fi

    # 如果仍未找到有效内核信息,跳过该版本
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      print_output "[-] No valid kernel information found for kernel ${ORANGE}${lK_VERSION}${NC}."
      continue
    fi

    # 检查ELF文件是否存在
    if ! [[ -f "${KERNEL_ELF_PATH}" ]]; then
      print_output "[-] Warning: Kernel ELF file not found"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi
    if ! [[ -v lK_VERSION ]]; then
      print_output "[-] Missing kernel version .. exit now"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi

    # ============================================================
    # 步骤2: 准备CVE详情路径
    # 尝试从SBOM获取bom-ref
    # ============================================================
    # local lCVE_DETAILS_PATH="${LOG_PATH_MODULE}""/linux_linux_kernel_${lK_VERSION}.txt"
    # try to find a bom-ref
    if ! lBOM_REF=$(jq -r '."bom-ref"' "${SBOM_LOG_PATH}"/linux_kernel_linux_kernel_*.json | sort -u | head -1); then
      local lBOM_REF="INVALID"
    fi
    local lPRODUCT_ARR=("linux_kernel")
    # shellcheck disable=SC2034
    local lVENDOR_ARR=("linux")
    local lCVE_DETAILS_PATH="${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_ARR[0]}_${lK_VERSION}.csv"

    # 提取内核架构
    if [[ -f "${KERNEL_ELF_PATH}" ]]; then
      extract_kernel_arch "${KERNEL_ELF_PATH}"
    fi

    # 标准化内核版本号(去掉末尾的.0)
    if [[ "${lK_VERSION}" == *".0" ]]; then
      lK_VERSION_KORG=${lK_VERSION%.0}
    else
      lK_VERSION_KORG="${lK_VERSION}"
    fi

    # ============================================================
    # 步骤3: 等待内核源码下载完成
    # 最多等待60次(5秒间隔 = 5分钟)
    # ============================================================
    # we need to wait for the downloaded linux kernel sources from the host
    local lWAIT_CNT=0
    while ! [[ -f "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" ]]; do
      print_output "[*] Waiting for kernel sources ..." "no_log"
      ((lWAIT_CNT+=1))
      # 超时或下载失败则跳到下一个版本
      if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... check for further kernel versions"
        continue 2
      fi
      sleep 5
    done

    # 现在有源码文件了,但可能下载不完整,需要继续等待验证
    # now we have a file with the kernel sources ... we do not know if this file is complete.
    # Probably it is just downloaded partly and we need to wait a bit longer
    lWAIT_CNT=0
    print_output "[*] Testing kernel sources ..." "no_log"
    # 使用gunzip -t测试压缩包完整性
    while ! gunzip -t "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" 2> /dev/null; do
      print_output "[*] Testing kernel sources ..." "no_log"
      ((lWAIT_CNT+=1))
      if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... check for further kernel versions"
        continue 2
      fi
      sleep 5
    done

    print_output "[*] Kernel sources for version ${ORANGE}${lK_VERSION}${NC} available"
    write_link "${LOG_DIR}/kernel_downloader.log"

    # ============================================================
    # 步骤4: 解压内核源码
    # ============================================================
    lKERNEL_DIR="${LOG_PATH_MODULE}/linux-${lK_VERSION_KORG}"
    [[ -d "${lKERNEL_DIR}" ]] && rm -rf "${lKERNEL_DIR}"
    if ! [[ -d "${lKERNEL_DIR}" ]] && [[ "$(file "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz")" == *"gzip compressed data"* ]]; then
      print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} extraction ... "
      tar -xzf "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" -C "${LOG_PATH_MODULE}"
    fi

    # ============================================================
    # 步骤5: 使用cve-bin-tool检测CVE
    # ============================================================
    print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} CVE detection ... "
    if ! grep -q "cve-bin-tool database preparation finished" "${TMP_DIR}/tmp_state_data.log"; then
      print_error "[-] cve-bin-tool database not prepared - cve analysis probably not working"
    fi
    cve_bin_tool_threader "${lBOM_REF}" "${lK_VERSION}" "${lORIG_SOURCE:-kernel_verification}" lVENDOR_ARR lPRODUCT_ARR

    export SYMBOLS_CNT=0

    # 检查CVE详情文件是否生成
    if ! [[ -f "${lCVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated ... check for further kernel version"
      continue
    fi

    # 读取所有检测到的CVE
    print_output "[*] Generate CVE vulnerabilities array for kernel version ${ORANGE}${lK_VERSION}${NC} ..." "no_log"
    mapfile -t lALL_KVULNS_ARR < <(tail -n+2 "${lCVE_DETAILS_PATH}" | sort -u -t, -k4,4)

    print_ln
    print_output "[+] Extracted ${ORANGE}${#lALL_KVULNS_ARR[@]}${GREEN} vulnerabilities based on kernel version only"
    write_link "${LOG_PATH_MODULE}""/kernel-${lK_VERSION}-vulns.log"

    # ============================================================
    # 步骤6: 编译内核(dry-run)获取使用的源文件
    # 需要配置文件和源码目录
    # ============================================================
    if [[ -f "${KERNEL_CONFIG_PATH}" ]] && [[ -d "${lKERNEL_DIR}" ]]; then
      compile_kernel "${KERNEL_CONFIG_PATH}" "${lKERNEL_DIR}" "${ORIG_K_ARCH}"
    fi

    # ============================================================
    # 步骤7: 提取内核符号
    # 从内核ELF文件和内核模块(.ko)中提取符号
    # ============================================================
    sub_module_title "Identify kernel symbols ..."
    # 使用readelf提取FUNC和OBJECT类型的符号
    readelf -W -s "${KERNEL_ELF_PATH}" | grep "FUNC\|OBJECT" | sed 's/.*FUNC//' | sed 's/.*OBJECT//' | awk '{print $4}' | \
      sed 's/\[\.\.\.\]//' > "${LOG_PATH_MODULE}"/symbols.txt || true
    SYMBOLS_CNT=$(wc -l < "${LOG_PATH_MODULE}"/symbols.txt)
    print_output "[*] Extracted ${ORANGE}${SYMBOLS_CNT}${NC} symbols from kernel (${KERNEL_ELF_PATH})"

    # 如果没有符号,无法进行后续验证
    if [[ "${SYMBOLS_CNT}" -eq 0 ]]; then
      print_output "[-] No symbols found for kernel ${lK_VERSION} - ${KERNEL_ELF_PATH}"
      print_output "[*] No further analysis possible for ${lK_VERSION} - ${KERNEL_ELF_PATH}"
      continue
    fi

    # 从固件目录中的内核模块提取额外符号
    if [[ -d "${LOG_DIR}""/firmware" ]]; then
      print_output "[*] Identify kernel modules and extract binary symbols ..." "no_log"
      # shellcheck disable=SC2016
      find "${LOG_DIR}/firmware" -name "*.ko" -print0|xargs -r -0 -P 16 -I % sh -c 'readelf -W -a "%" | grep FUNC | sed "s/.*FUNC//" | awk "{print $4}" | sed "s/\[\.\.\.\]//"' >> "${LOG_PATH_MODULE}"/symbols.txt || true
    fi

    # 去重并统计唯一符号
    uniq "${LOG_PATH_MODULE}"/symbols.txt > "${LOG_PATH_MODULE}"/symbols_uniq.txt
    SYMBOLS_CNT=$(wc -l < "${LOG_PATH_MODULE}"/symbols_uniq.txt)

    print_ln
    print_output "[+] Extracted ${ORANGE}${SYMBOLS_CNT}${GREEN} unique symbols (kernel+modules)"
    write_link "${LOG_PATH_MODULE}/symbols_uniq.txt"
    print_ln
    # 将符号文件分割以便并行处理
    split_symbols_file

    # ============================================================
    # 步骤8: 并行验证每个CVE漏洞
    # ============================================================
    sub_module_title "Linux kernel vulnerability verification"

    print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC}" "" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    print_ln

    local lVULN=""
    for lVULN in "${lALL_KVULNS_ARR[@]}"; do
      vuln_checker_threader "${lVULN}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S26_ARR_MAIN+=( "${lTMP_PID}" )
      ((VULN_CNT+=1))
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S26_ARR_MAIN
    done

    # 等待所有CVE验证完成
    wait_for_pid "${lWAIT_PIDS_S26_ARR_MAIN[@]}"

    # 生成最终漏洞报告
    final_log_kernel_vulns "${lK_VERSION}" "${lALL_KVULNS_ARR[@]}"
  done

  # ============================================================
  # 步骤9: 更新漏洞汇总报告,添加已验证的CVE信息
  # ============================================================
  # fix the CVE log file and add the verified vulnerabilities:
  if [[ -f "${LOG_PATH_MODULE}/vuln_summary.txt" ]]; then
    # extract the verified CVEs:
    # 从CVE结果CSV中提取已验证的CVE(第6或7字段为1表示已验证)
    local lVERIFIED_KERNEL_VERS_ARR=()
    local lVERIFIED_KVERS=""
    mapfile -t lVERIFIED_KERNEL_VERS_ARR < <(cut -d ';' -f1,3,6,7 "${LOG_PATH_MODULE}"/cve_results_kernel_*.csv | grep ";1;\|;1$" | cut -d ';' -f1 | sort -u || true)

    if [[ "${#lVERIFIED_KERNEL_VERS_ARR[@]}" -gt 0 ]]; then
      for lVERIFIED_KVERS in "${lVERIFIED_KERNEL_VERS_ARR[@]}"; do
        local lVERIFIED_CVE_ARR_PER_VERSION=()
        # 获取每个版本下已验证的CVE列表
        mapfile -t lVERIFIED_CVE_ARR_PER_VERSION < <(grep -h "^${lVERIFIED_KVERS}" "${LOG_PATH_MODULE}"/cve_results_kernel_*.csv | cut -d ';' -f3,6,7 | grep ";1;\|;1$" | cut -d ';' -f1 | sort -u || true)

        local lTMP_CVE_ENTRY=""
        local lFULL_ENTRY_LINE=""
        # get the CVEs part of vuln_summary.txt
        # 查找漏洞汇总中对应版本的条目
        lFULL_ENTRY_LINE=$(grep -E "${lVERIFIED_KVERS}.*:\s+CVEs:\ [0-9]+\s+:" "${LOG_PATH_MODULE}/vuln_summary.txt" || true)
        [[ -z "${lFULL_ENTRY_LINE}" ]] && continue
        # 提取CVEs数量部分
        lTMP_CVE_ENTRY=$(echo "${lFULL_ENTRY_LINE}" | grep -o -E ":\s+CVEs:\ [0-9]+\s+:" || true)
        # 替换空格为已验证数量 -> :  CVEs: 1234 (123):
        lTMP_CVE_ENTRY=$(echo "${lTMP_CVE_ENTRY}" | sed -r 's/(CVEs:\ [0-9]+)\s+/\1 ('"${#lVERIFIED_CVE_ARR_PER_VERSION[@]}"')/')
        # 确保长度正确 -> :  CVEs: 1234 (123)  :
        lTMP_CVE_ENTRY=$(printf '%s%*s' "${lTMP_CVE_ENTRY%:}" "$((22-"${#lTMP_CVE_ENTRY}"))" ":")

        # final replacement in file:
        # 将修改后的条目写回文件
        echo "${lFULL_ENTRY_LINE}" | sed -r 's/:\s+CVEs:\ [0-9]+\s+:/'"${lTMP_CVE_ENTRY}"'/' >> "${LOG_PATH_MODULE}/vuln_summary_new.txt"

        # 标记已验证的CVE
        for lVERIFIED_BB_CVE in "${lVERIFIED_CVE_ARR_PER_VERSION[@]}"; do
          # print_output "[*] Replacing ${lVERIFIED_BB_CVE} in ${LOG_PATH_MODULE}/cve_sum/*_finished.txt" "no_log"
          local lV_ENTRY="(V)"
          # ensure we have the correct length
          # shellcheck disable=SC2183
          lV_ENTRY=$(printf '%s%*s' "${lV_ENTRY}" "$((19-"${#lVERIFIED_BB_CVE}"-"${#lV_ENTRY}"))")
          sed -i -r 's/('"${lVERIFIED_BB_CVE}"')\s+/\1 '"${lV_ENTRY}"'/' "${LOG_PATH_MODULE}/cve_sum/"*"${lVERIFIED_KVERS}"_finished.txt || true
        done
      done

      # 合并新旧汇总文件
      if [[ -f "${LOG_PATH_MODULE}/vuln_summary_new.txt" ]]; then
        local lVULN_SUMMARY_ENTRY=""
        while read -r  lVULN_SUMMARY_ENTRY; do
          local lkVERSION=""
          lkVERSION=$(echo "${lVULN_SUMMARY_ENTRY}" | cut -d ':' -f3)
          # remove all spaces
          lkVERSION="${lkVERSION//\ }"
          if grep -q "${lkVERSION}" "${LOG_PATH_MODULE}/vuln_summary_new.txt"; then
            continue
          fi
          echo "${lVULN_SUMMARY_ENTRY}" >> "${LOG_PATH_MODULE}/vuln_summary_new.txt"
        done < "${LOG_PATH_MODULE}/vuln_summary.txt"
        mv "${LOG_PATH_MODULE}/vuln_summary_new.txt" "${LOG_PATH_MODULE}/vuln_summary.txt" || true
      fi
    fi
  fi

  # 记录模块结束
  module_end_log "${FUNCNAME[0]}" "${VULN_CNT}"
}

# ==========================================================================================
# vuln_checker_threader - CVE漏洞检查线程函数
#
# 功能:
#   对单个CVE漏洞进行检查和验证
#
# 验证流程:
#   1. 从CVE条目提取CVE编号
#   2. 从NVD数据库获取CVE详细描述
#   3. 从描述中提取受影响的源文件路径
#   4. 对每个路径执行符号验证和编译验证
#   5. 记录验证结果
#
# 参数:
#   $1 - lVULN: CVE漏洞条目(CSV格式)
# ==========================================================================================
vuln_checker_threader() {
  local lVULN="${1:-}"                # CVE漏洞条目
  local lK_PATHS_ARR=()              # 内核路径数组
  local lK_PATHS_FILES_TMP_ARR=()    # 临时路径数组(用于无路径的文件名)
  local lSUMMARY=""                  # CVE描述摘要
  local lCVSS3=""                    # CVSSv3评分

  # lK_PATH是备用文本,如果lK_PATHS_ARR为空时用于输出
  local lK_PATH="missing vulnerability path from advisory"

  # print_output "[*] VULN data: ${lVULN}" "no_log"
  # 从CSV第4字段提取CVE编号
  lCVE=$(echo "${lVULN}" | cut -d, -f4)
  if ! [[ "${lCVE}" == "CVE-"* ]]; then
    print_output "[-] No CVE identifier extracted for ${lVULN} ..."
    return
  fi

  # 输出进度信息
  local lOUTx="[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#lALL_KVULNS_ARR[@]}${NC} / ${ORANGE}${lCVE}${NC}"
  print_output "${lOUTx}" "no_log"
  write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"

  # 从CSV第6字段提取CVSSv3评分
  lCVSS3="$(echo "${lVULN}" | cut -d, -f6)"
  # lSUMMARY="$(echo "${lVULN}" | cut -d: -f6-)"

  # 从NVD JSON文件中提取英文描述
  # NVD目录结构: ${NVD_DIR}/${CVE年份}/CVE-${年份}-${编号}.json
  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE%-*}/${lCVE:0:11}"*"xx/${lCVE}.json" 2>/dev/null || true)

  # print_output "$(indent "CVSSv3: ${ORANGE}${lCVSS3}${NC} / Summary: ${ORANGE}${lSUMMARY}${NC}")"

  # ============================================================
  # 从CVE描述中提取内核源文件路径
  # 路径可能包含:
  #   - 完整路径: net/ipv4/ip_sockglue.c
  #   - 相对路径: ip_sockglue.c (需要查找)
  # 支持的文件类型: .c, .h, .S (汇编源文件)
  # ============================================================
  # extract kernel source paths from summary -> we use these paths to check if they are used by our
  # symbols or during kernel compilation
  # 处理流程:
  #   1. 将空格替换为换行,便于逐行处理
  #   2. 移除行尾反斜杠(续行符)
  #   3. 筛选.c/.h/.S文件
  #   4. 移除CVE编号前缀
  #   5. 清理各种括号和标点
  #   6. 提取文件名(去掉行号)
  mapfile -t lK_PATHS_ARR < <(echo "${lSUMMARY}" | tr ' ' '\n' | sed 's/\\$//' | grep ".*\.[chS]$" | sed -r 's/CVE-[0-9]+-[0-9]+:[0-9].*://' \
    | sed -r 's/CVE-[0-9]+-[0-9]+:null.*://' | sed 's/^(//' | sed 's/)$//' | sed 's/,$//' | sed 's/\.$//' | cut -d: -f1 || true)

  # 对没有完整路径的文件名,在内核源码中查找匹配文件
  for lK_PATH in "${lK_PATHS_ARR[@]}"; do
    # we have only a filename without path -> we search for possible candidate files in the kernel sources
    if ! [[ "${lK_PATH}" == *"/"* ]]; then
      lOUTx="[*] Found file name ${ORANGE}${lK_PATH}${NC} for ${ORANGE}${lCVE}${NC} without path details ... looking for candidates now"
      print_output "${lOUTx}" "no_log"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      # 在内核源码目录中查找同名文件
      mapfile -t lK_PATHS_FILES_TMP_ARR < <(find "${lKERNEL_DIR}" -name "${lK_PATH}" | sed "s&${lKERNEL_DIR}\/&&")
    fi
    # 将找到的完整路径添加到数组
    lK_PATHS_ARR+=("${lK_PATHS_FILES_TMP_ARR[@]}")
  done

  # ============================================================
  # 对每个找到的路径进行验证
  # ============================================================
  if [[ "${#lK_PATHS_ARR[@]}" -gt 0 ]]; then
    for lK_PATH in "${lK_PATHS_ARR[@]}"; do
      # 检查文件是否存在于内核源码中
      if [[ -f "${lKERNEL_DIR}/${lK_PATH}" ]]; then
        # 检查是否是架构相关路径
        # check if arch is in path -> if so we check if our architecture is also in the path
        # if we find our architecture then we can proceed with symbol_verifier
        if [[ "${lK_PATH}" == "arch/"* ]]; then
          # 验证架构是否匹配
          if [[ "${lK_PATH}" == "arch/${ORIG_K_ARCH}/"* ]]; then
            # 记录找到的路径数量
            write_log "lCNT_PATHS_FOUND" "${TMP_DIR}/s25_counting.tmp"
            # 如果有符号信息,进行符号验证
            if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
              symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" "${lKERNEL_DIR}" &
              lWAIT_PIDS_S26_ARR+=( "$!" )
            fi
            # 如果有编译信息,进行编译验证
            if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
              compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" &
              lWAIT_PIDS_S26_ARR+=( "$!" )
            fi
          else
            # 此漏洞针对不同架构,跳过
            # this vulnerability is for a different architecture -> we can skip it for our kernel
            lOUTx="[-] Vulnerable path for different architecture found for ${ORANGE}${lK_PATH}${NC} - not further processing ${ORANGE}${lCVE}${NC}"
            print_output "${lOUTx}" "no_log"
            write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
            write_log "lCNT_PATHS_FOUND_WRONG_ARCH" "${TMP_DIR}/s25_counting.tmp"
          fi
        else
          # 非架构相关路径,直接验证
          write_log "lCNT_PATHS_FOUND" "${TMP_DIR}/s25_counting.tmp"
          if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
            symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" "${lKERNEL_DIR}" &
            lWAIT_PIDS_S26_ARR+=( "$!" )
          fi
          if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
            compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" &
            lWAIT_PIDS_S26_ARR+=( "$!" )
          fi
        fi
      else
        # 源码文件中不存在,无漏洞
        # no source file in our kernel sources -> no vulns
        lOUTx="[-] ${ORANGE}${lCVE}${NC} - ${ORANGE}${lK_PATH}${NC} - vulnerable source file not found in kernel sources"
        print_output "${lOUTx}" "no_log"
        write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
        write_log "lCNT_PATHS_NOT_FOUND" "${TMP_DIR}/s25_counting.tmp"
      fi
      # 限制并发数量
      max_pids_protection 20 lWAIT_PIDS_S26_ARR
    done
  else
    # 无法提取路径信息
    lOUTx="[-] ${lCVE} - ${lK_PATH}"
    print_output "${lOUTx}" "no_log"
    write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    write_log "lCNT_PATHS_UNK" "${TMP_DIR}/s25_counting.tmp"
  fi
  # 等待所有验证任务完成
  wait_for_pid "${lWAIT_PIDS_S26_ARR[@]}"
}

# ==========================================================================================
# split_symbols_file - 将符号文件分割以便并行处理
#
# 功能:
#   由于符号文件可能很大,将它们分割成小文件以便并行验证
#   分割成100个符号一组的小文件
#
# 输出文件:
#   - symbols_uniq.split.*: 用于匹配EXPORT_SYMBOL
#   - symbols_uniq.split_gpl.*: 用于匹配EXPORT_SYMBOL_GPL
#
# 格式转换:
#   原格式: symbol_name
#   转换后: EXPORT_SYMBOL(symbol_name)
#           EXPORT_SYMBOL_GPL(symbol_name)
# ==========================================================================================
split_symbols_file() {
  print_output "[*] Splitting symbols file for processing ..." "no_log"
  # 将符号文件按100行分割
  split -l 100 "${LOG_PATH_MODULE}"/symbols_uniq.txt "${LOG_PATH_MODULE}"/symbols_uniq.split.
  # 添加EXPORT_SYMBOL前缀和括号后缀
  sed -i 's/^/EXPORT_SYMBOL\(/' "${LOG_PATH_MODULE}"/symbols_uniq.split.*
  sed -i 's/$/\)/' "${LOG_PATH_MODULE}"/symbols_uniq.split.*

  # 同样处理GPL版本
  split -l 100 "${LOG_PATH_MODULE}"/symbols_uniq.txt "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.
  sed -i 's/^/EXPORT_SYMBOL_GPL\(/' "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*
  sed -i 's/$/\)/' "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*
  print_output "[*] Splitting symbols file for processing ... done" "no_log"
}

# ==========================================================================================
# extract_kernel_arch - 从内核ELF文件提取处理器架构
#
# 功能:
#   从预处理的CSV日志中查找内核的架构信息
#   并将其标准化为内核源码中使用的架构名称
#
# 支持的架构映射:
#   ARM aarch64 -> ARM64
#   ARM64 -> ARM64
#   ARM32 -> ARM
#   ELF 32-bit ARM -> ARM
#   MIPS -> MIPS
#   PowerPC -> powerpc
#   Altera Nios II -> nios2
#   Intel x86 -> x86
#
# 参数:
#   $1 - lKERNEL_ELF_PATH: 内核ELF文件路径
#
# 全局变量:
#   ORIG_K_ARCH: 提取并标准化后的架构名称
# ==========================================================================================
extract_kernel_arch() {
  local lKERNEL_ELF_PATH="${1:-}"
  export ORIG_K_ARCH=""

  # 从P99 CSV日志中查找该ELF文件的架构信息(第8字段)
  ORIG_K_ARCH=$(grep ";${lKERNEL_ELF_PATH};" "${P99_CSV_LOG}" | cut -d ';' -f8 || true)

  # ARM架构标准化
  if [[ "${ORIG_K_ARCH}" == *"ARM aarch64"* ]]; then
    # for ARM -> ARM aarch64 to ARM64
    ORIG_K_ARCH="ARM64"
  elif [[ "${ORIG_K_ARCH}" == *"ARM64"* ]]; then
    # for ARM -> ARM aarch64 to ARM64
    ORIG_K_ARCH="ARM64"
  elif [[ "${ORIG_K_ARCH}" == *"ARM32"* ]]; then
    ORIG_K_ARCH="ARM"
  elif [[ "${ORIG_K_ARCH}" == *"ELF 32"*"ARM"* ]]; then
    ORIG_K_ARCH="ARM"
  fi

  # MIPS架构
  if [[ "${ORIG_K_ARCH}" == *"MIPS"* ]]; then
    ORIG_K_ARCH="MIPS"
  fi

  # PowerPC架构(内核使用小写)
  if [[ "${ORIG_K_ARCH}" == *"PowerPC"* ]]; then
    ORIG_K_ARCH="powerpc"
  fi

  # Nios II架构
  if [[ "${ORIG_K_ARCH}" == *"Altera Nios II"* ]]; then
    ORIG_K_ARCH="nios2"
  fi

  # x86架构
  if [[ "${ORIG_K_ARCH}" == *"Intel"* ]]; then
    ORIG_K_ARCH="x86"
  fi

  # 转换为小写并移除空格
  ORIG_K_ARCH="${ORIG_K_ARCH,,}"
  ORIG_K_ARCH="${ORIG_K_ARCH//\ }"
  print_output "[+] Identified kernel architecture ${ORANGE}${ORIG_K_ARCH}${NC}"
}

symbol_verifier() {
  local lCVE="${1:-}"
  local lK_VERSION="${2:-}"
  local lK_PATH="${3:-}"
  local lCVSS="${4:-}"
  local lKERNEL_DIR="${5:-}"
  local lVULN_FOUND=0
  local lCHUNK_FILE=""

  for lCHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split.* ; do
    # echo "testing chunk file $lCHUNK_FILE"
    if grep -q -f "${lCHUNK_FILE}" "${lKERNEL_DIR}/${lK_PATH}" ; then
      # echo "verified chunk file $lCHUNK_FILE"
      local lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - exported symbol${NC}"
      print_output "${lOUTx}"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - exported symbol verified - ${lK_PATH}" >> "${LOG_PATH_MODULE}""/${lCVE}_symbol_verified.txt"
      lVULN_FOUND=1
      break
    fi
  done

  # if we have already a match for this path we can skip the 2nd check
  # this is only for speed up the process a bit
  [[ "${lVULN_FOUND}" -eq 1 ]] && return

  for lCHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.* ; do
    # echo "testing chunk file $lCHUNK_FILE"
    if grep -q -f "${lCHUNK_FILE}" "${lKERNEL_DIR}/${lK_PATH}" ; then
      # print_output "[*] verified chunk file $lCHUNK_FILE (GPL)"
      local lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - exported symbol (GPL)${NC}"
      print_output "${lOUTx}"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - exported symbol verified (gpl) - ${lK_PATH}" >> "${LOG_PATH_MODULE}""/${lCVE}_symbol_verified.txt"
      lVULN_FOUND=1
      break
    fi
  done
}

# ==========================================================================================
# compile_verifier - 编译验证函数
#
# 功能:
#   检查CVE中提到的源文件是否在编译过程中实际被使用
#   与symbol_verifier配合使用,双重验证漏洞相关性
#
# 参数:
#   $1 - lCVE: CVE编号
#   $2 - lK_VERSION: 内核版本
#   $3 - lK_PATH: 源文件路径
#   $4 - lCVSS: CVSS评分
#
# 输出:
#   创建${CVE}_compiled_verified.txt文件记录验证成功的CVE
# ==========================================================================================
compile_verifier() {
  local lCVE="${1:-}"
  local lK_VERSION="${2:-}"
  local lK_PATH="${3:-}"
  local lCVSS="${4:-}"
  # 如果没有编译验证日志文件,直接返回
  if ! [[ -f "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ]]; then
    return
  fi

  # 检查源文件路径是否在编译使用的文件列表中
  if grep -q "${lK_PATH}" "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ; then
    print_output "[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - compiled path${NC}"
    echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - compiled path verified - ${lK_PATH}" >> "${LOG_PATH_MODULE}""/${lCVE}_compiled_verified.txt"
  fi
}

# ==========================================================================================
# compile_kernel - 内核编译(干跑模式)获取使用的源文件
#
# 原理说明:
#   本函数基于论文 https://arxiv.org/pdf/2209.05217.pdf 的方法
#   使用内核编译器的干跑模式(-Bndi)来获取编译过程中实际使用的源文件列表
#   而不需要真正编译内核,节省大量时间
#
# 工作流程:
#   1. 检查配置文件和源码目录是否存在
#   2. 检查架构目录是否支持
#   3. 复制固件的配置到内核源码
#   4. 运行make olddefconfig更新配置
#   5. 运行make -Bndi进行干跑,获取使用的源文件列表
#   6. 验证源文件是否真实存在于源码目录
#
# 参数:
#   $1 - lKERNEL_CONFIG_FILE: 内核配置文件路径
#   $2 - lKERNEL_DIR: 内核源码目录
#   $3 - lKARCH: 处理器架构
#
# 输出:
#   - kernel-compile-files.log: 所有编译使用的源文件
#   - kernel-compile-files_verified.log: 验证存在的源文件
# ==========================================================================================
compile_kernel() {
  # this is based on the great work shown here https://arxiv.org/pdf/2209.05217.pdf
  local lKERNEL_CONFIG_FILE="${1:-}"
  local lKERNEL_DIR="${2:-}"
  local lKARCH="${3:-}"
  # lKARCH=$(echo "${lKARCH}" | tr '[:upper:]' '[:lower:]')
  # 转换为小写
  lKARCH="${lKARCH,,}"
  export COMPILE_SOURCE_FILES=0
  export COMPILE_SOURCE_FILES_VERIFIED=0

  # 检查配置文件是否存在
  if ! [[ -f "${lKERNEL_CONFIG_FILE}" ]]; then
    print_output "[-] No supported kernel config found - ${ORANGE}${lKERNEL_CONFIG_FILE}${NC}"
    return
  fi
  # 检查源码目录是否存在
  if ! [[ -d "${lKERNEL_DIR}" ]]; then
    print_output "[-] No supported kernel source directory found - ${ORANGE}${lKERNEL_DIR}${NC}"
    return
  fi
  print_ln
  sub_module_title "Compile Linux kernel - dry run mode"

  # 检查架构目录是否存在
  if ! [[ -d "${lKERNEL_DIR}"/arch/"${lKARCH}" ]]; then
    print_output "[!] No supported architecture found - ${ORANGE}${lKARCH}${NC}"
    return
  else
    print_output "[*] Supported architecture found - ${ORANGE}${lKARCH}${NC}"
  fi

  # 切换到内核源码目录
  cd "${lKERNEL_DIR}" || exit
  # print_output "[*] Create default kernel config for $ORANGE$lKARCH$NC architecture"
  # LANG=en make ARCH="${lKARCH}" defconfig | tee -a "${LOG_PATH_MODULE}"/kernel-compile-defconfig.log || true
  # print_output "[*] Finished creating default kernel config for $ORANGE$lKARCH$NC architecture" "" "$LOG_PATH_MODULE/kernel-compile-defconfig.log"
  print_ln

  # 安装固件中提取的内核配置
  print_output "[*] Install kernel config of the identified configuration of the firmware"
  cp "${lKERNEL_CONFIG_FILE}" .config
  # 运行make olddefconfig更新配置选项(对于新选项使用默认值)
  # https://stackoverflow.com/questions/4178526/what-does-make-oldconfig-do-exactly-in-the-linux-kernel-makefile
  local LANG=""
  LANG=en make ARCH="${lKARCH}" olddefconfig | tee -a "${LOG_PATH_MODULE}"/kernel-compile-olddefconfig.log || true
  print_output "[*] Finished updating kernel config with the identified firmware configuration" "" "${LOG_PATH_MODULE}/kernel-compile-olddefconfig.log"
  print_ln

  # 干跑模式编译:
  # -B: 不实际运行命令(只显示会执行什么)
  # -n: dry-run模式
  # -d: 生成dependency文件
  # -i: 忽略错误,继续执行
  print_output "[*] Starting kernel compile dry run ..."
  LANG=en make ARCH="${lKARCH}" target=all -Bndi | tee -a "${LOG_PATH_MODULE}"/kernel-compile.log
  print_ln
  print_output "[*] Finished kernel compile dry run ... generated used source files" "" "${LOG_PATH_MODULE}/kernel-compile.log"

  # 返回原始工作目录
  cd "${HOME_DIR}" || exit

  # 处理编译输出,提取源文件列表
  if [[ -f "${LOG_PATH_MODULE}"/kernel-compile.log ]]; then
    # 处理流程:
    # 1. 将空格替换为换行
    # 2. 筛选.c/.h/.S文件
    # 3. 移除各种引号和括号
    # 4. 移除相对路径前缀
    # 5. 移除绝对路径
    # 6. 去重排序
    tr ' ' '\n' < "${LOG_PATH_MODULE}"/kernel-compile.log | grep ".*\.[chS]" | tr -d '"' | tr -d ')' | tr -d '<' | tr -d '>' \
      | tr -d '(' | sed 's/^\.\///' | sed '/^\/.*/d' | tr -d ';' | sed 's/^>//' | sed 's/^-o//' | tr -d \' \
      | sed 's/--defines=//' | sed 's/\.$//' | sort -u > "${LOG_PATH_MODULE}"/kernel-compile-files.log
    COMPILE_SOURCE_FILES=$(wc -l < "${LOG_PATH_MODULE}"/kernel-compile-files.log)
    print_output "[+] Found ${ORANGE}${COMPILE_SOURCE_FILES}${GREEN} used source files during compilation" "" "${LOG_PATH_MODULE}/kernel-compile-files.log"

    # 验证提取的源文件是否真实存在于源码目录
    # lets check the entries and verify them in our kernel sources
    # entries without a real file are not further processed
    # with this mechanism we can eliminate garbage
    while read -r COMPILE_SOURCE_FILE; do
      if [[ -f "${lKERNEL_DIR}""/""${COMPILE_SOURCE_FILE}" ]]; then
        # print_output "[*] Verified Source file $ORANGE$lKERNEL_DIR/$COMPILE_SOURCE_FILE$NC is available"
        # 只记录真实存在的文件
        echo "${COMPILE_SOURCE_FILE}" >> "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log
      fi
    done < "${LOG_PATH_MODULE}"/kernel-compile-files.log
    COMPILE_SOURCE_FILES_VERIFIED=$(wc -l < "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log)
    print_ln
    print_output "[+] Found ${ORANGE}${COMPILE_SOURCE_FILES_VERIFIED}${GREEN} used and available source files during compilation" "" "${LOG_PATH_MODULE}/kernel-compile-files_verified.log"
  else
    print_output "[-] Found ${RED}NO${NC} used source files during compilation"
  fi
}

# ==========================================================================================
# report_kvulns_csv - 生成CVE漏洞CSV报告
#
# 功能:
#   将单个CVE的验证结果写入CSV文件
#   记录CVE编号、版本、架构、CVSS评分和验证状态
#
# 参数:
#   $1 - lVULN: CVE漏洞条目
#   $2 - lK_VERSION: 内核版本
#
# CSV格式:
#   Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files
# ==========================================================================================
report_kvulns_csv() {
  local lVULN="${1:-}"
  local lK_VERSION="${2:-}"
  local lCVE=""
  local lCVSS3=""
  local lCVE_SYMBOL_FOUND=0
  local lCVE_COMPILE_FOUND=0

  # 从漏洞条目提取CVE编号(第4字段)
  lCVE=$(echo "${lVULN}" | cut -d, -f4)
  # 提取CVSSv3评分(第6字段)
  lCVSS="$(echo "${lVULN}" | cut -d, -f6)"
  # 检查是否存在符号验证文件(值为1表示已验证)
  lCVE_SYMBOL_FOUND=$(find "${LOG_PATH_MODULE}" -maxdepth 1 -name "${lCVE}_symbol_verified.txt" | wc -l)
  # 检查是否存在编译验证文件(值为1表示已验证)
  lCVE_COMPILE_FOUND=$(find "${LOG_PATH_MODULE}" -maxdepth 1 -name "${lCVE}_compiled_verified.txt" | wc -l)
  # 写入CSV日志
  write_log "${lK_VERSION};${ORIG_K_ARCH};${lCVE};NA;${lCVSS};${lCVE_SYMBOL_FOUND:-0};${lCVE_COMPILE_FOUND:-0}" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv
}

# ==========================================================================================
# final_log_kernel_vulns - 生成最终内核漏洞报告
#
# 功能:
#   汇总所有CVE验证结果,生成最终报告
#
# 报告内容包括:
#   - CVE总数和验证统计
#   - 路径统计(未知/未找到/找到/架构不匹配)
#   - 符号验证统计
#   - 编译验证统计
#   - 高危CVE列表(CVSS >= 9.0)
#
# 参数:
#   $1 - lK_VERSION: 内核版本
#   $@ - lALL_KVULNS_ARR: 所有漏洞数组
# ==========================================================================================
final_log_kernel_vulns() {
  sub_module_title "Linux kernel verification results"
  local lK_VERSION="${1:-}"
  shift
  local lALL_KVULNS_ARR=("$@")

  if ! [[ -v lALL_KVULNS_ARR ]]; then
    print_output "[-] No module results"
    return
  fi

  find "${LOG_PATH_MODULE}" -maxdepth 1 -name "symbols_uniq.split.*" -delete || true
  find "${LOG_PATH_MODULE}" -maxdepth 1 -name "symbols_uniq.split_gpl.*" -delete || true

  local lVULN=""
  local lSYM_USAGE_VERIFIED=0
  local lVULN_PATHS_VERIFIED_SYMBOLS=0
  local lVULN_PATHS_VERIFIED_COMPILED=0
  local lCVE_VERIFIED_SYMBOLS=0
  local lCVE_VERIFIED_COMPILED=0
  local lCVE_VERIFIED_ONE=0
  local lCVE_VERIFIED_OVERLAP=0
  local lCVE_VERIFIED_OVERLAP_CRITICAL_ARR=()
  local lCVE_VERIFIED_ONE_CRITICAL_ARR=()
  local lCVE_VERIFIED_ONE_CRITICAL=""
  local lCVE_VERIFIED_OVERLAP_CRITICAL_ARR=()
  local lCVE_CRITICAL=""
  local lCVSS2_CRITICAL=""
  local lCVSS3_CRITICAL=""
  local lWAIT_PIDS_S26_1_ARR=()

  print_output "[*] Generating final kernel report ..." "no_log"
  write_log "Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv

  if [[ -f "${LOG_PATH_MODULE}/kernel_cve_version_issues.log" ]]; then
    print_output "[*] Multiple possible version mismatches identified and reported."
    write_link "${LOG_PATH_MODULE}/kernel_cve_version_issues.log"
  fi
  # we walk through the original version based kernel vulnerabilities and report the results
  # from symbols and kernel configuration
  for lVULN in "${lALL_KVULNS_ARR[@]}"; do
    report_kvulns_csv "${lVULN}" "${lK_VERSION}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S26_1_ARR+=( "${lTMP_PID}" )
    max_pids_protection $((2*"${MAX_MOD_THREADS}")) lWAIT_PIDS_S26_1_ARR
  done

  lSYM_USAGE_VERIFIED=$(wc -l "${LOG_PATH_MODULE}"/CVE-*symbol_* 2>/dev/null | tail -n1 | awk '{print $1}' || echo 0)
  # nosemgrep
  lVULN_PATHS_VERIFIED_SYMBOLS=$(cat "${LOG_PATH_MODULE}"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | sed 's/.*verified - //' | sed 's/.*verified (GPL) - //' | sort -u | wc -l || true)
  # nosemgrep
  lVULN_PATHS_VERIFIED_COMPILED=$(cat "${LOG_PATH_MODULE}"/CVE-*compiled_verified.txt 2>/dev/null | grep "compiled path verified" | sed 's/.*verified - //' | sort -u | wc -l || true)
  # nosemgrep
  lCVE_VERIFIED_SYMBOLS=$(cat "${LOG_PATH_MODULE}"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | cut -d\  -f1 | sort -u | wc -l || true)
  # nosemgrep
  lCVE_VERIFIED_COMPILED=$(cat "${LOG_PATH_MODULE}"/CVE-*compiled_verified.txt 2>/dev/null| grep "compiled path verified" | cut -d\  -f1 | sort -u | wc -l || true)

  print_output "[+] Identified ${ORANGE}${#lALL_KVULNS_ARR[@]}${GREEN} unverified CVE vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC}"
  write_link "${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"
  print_output "[*] Detected architecture ${ORANGE}${ORIG_K_ARCH}${NC}"
  print_output "[*] Extracted ${ORANGE}${SYMBOLS_CNT}${NC} unique symbols from kernel and modules"
  write_link "${LOG_PATH_MODULE}/symbols_uniq.txt"
  if [[ -v COMPILE_SOURCE_FILES ]]; then
    print_output "[*] Extracted ${ORANGE}${COMPILE_SOURCE_FILES}${NC} used source files during compilation"
  fi

  local lCNT_PATHS_UNK=0
  local lCNT_PATHS_NOT_FOUND=0
  local lCNT_PATHS_FOUND=0
  local lCNT_PATHS_FOUND_WRONG_ARCH=0

  if [[ -s "${TMP_DIR}/s25_counting.tmp" ]]; then
    lCNT_PATHS_UNK=$(grep -c "lCNT_PATHS_UNK" "${TMP_DIR}/s25_counting.tmp")
    lCNT_PATHS_NOT_FOUND=$(grep -c "lCNT_PATHS_NOT_FOUND" "${TMP_DIR}/s25_counting.tmp")
    lCNT_PATHS_FOUND=$(grep -c "lCNT_PATHS_FOUND" "${TMP_DIR}/s25_counting.tmp")
    lCNT_PATHS_FOUND_WRONG_ARCH=$(grep -c "lCNT_PATHS_FOUND_WRONG_ARCH" "${TMP_DIR}/s25_counting.tmp")
  fi

  print_output "[*] Found ${ORANGE}${lCNT_PATHS_UNK}${NC} advisories with missing vulnerable path details"
  print_output "[*] Found ${ORANGE}${lCNT_PATHS_NOT_FOUND}${NC} path details in CVE advisories but no real kernel path found in vanilla kernel source"
  print_output "[*] Found ${ORANGE}${lCNT_PATHS_FOUND}${NC} path details in CVE advisories with real kernel path"
  print_output "[*] Found ${ORANGE}${lCNT_PATHS_FOUND_WRONG_ARCH}${NC} path details in CVE advisories with real kernel path but wrong architecture"
  print_output "[*] ${ORANGE}${lSYM_USAGE_VERIFIED}${NC} symbol usage verified"
  print_output "[*] ${ORANGE}${lVULN_PATHS_VERIFIED_SYMBOLS}${NC} vulnerable paths verified via symbols"
  print_output "[*] ${ORANGE}${lVULN_PATHS_VERIFIED_COMPILED}${NC} vulnerable paths verified via compiled paths"
  print_ln

  # we need to wait for the cve_results_kernel_"${lK_VERSION}".csv
  wait_for_pid "${lWAIT_PIDS_S26_1_ARR[@]}"

  lCVE_VERIFIED_ONE=$(cut -d\; -f6-7 "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv | grep -c "1" || true)
  lCVE_VERIFIED_OVERLAP=$(grep -c ";1;1" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv || true)
  mapfile -t lCVE_VERIFIED_OVERLAP_CRITICAL_ARR < <(grep ";1;1$" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv | grep ";9.[0-9];\|;10;" || true)
  mapfile -t lCVE_VERIFIED_ONE_CRITICAL_ARR < <(grep ";1;\|;1$" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv | grep ";9.[0-9];\|;10;" || true)

  if [[ "${lCVE_VERIFIED_SYMBOLS}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_SYMBOLS}${GREEN} (exported symbols)"
  fi
  if [[ "${lCVE_VERIFIED_COMPILED}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_COMPILED}${GREEN} (compiled paths)"
  fi
  if [[ "${lCVE_VERIFIED_ONE}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_ONE}${GREEN} (one mechanism succeeded)"
  fi
  if [[ "${lCVE_VERIFIED_OVERLAP}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_OVERLAP}${GREEN} (both mechanisms overlap)"
  fi

  # 输出高危CVE(CVSS >= 9.0)的验证结果
  if [[ "${#lCVE_VERIFIED_ONE_CRITICAL_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: ${ORANGE}${#lCVE_VERIFIED_ONE_CRITICAL_ARR[@]}${GREEN} (one mechanism succeeded)"
    for lCVE_VERIFIED_ONE_CRITICAL in "${lCVE_VERIFIED_ONE_CRITICAL_ARR[@]}"; do
      lCVE_CRITICAL=$(echo "${lCVE_VERIFIED_ONE_CRITICAL}" | cut -d\; -f3)
      lCVSS2_CRITICAL=$(echo "${lCVE_VERIFIED_ONE_CRITICAL}" | cut -d\; -f4)
      lCVSS3_CRITICAL=$(echo "${lCVE_VERIFIED_ONE_CRITICAL}" | cut -d\; -f5)
      # disabled because it is too slow
      # identify_exploits "${lCVE_CRITICAL}"
      if [[ "${EXPLOIT_DETECTED:-"no"}" == "yes" ]] || [[ "${POC_DETECTED:-"no"}" == "yes" ]]; then
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}\t-\tExploit/PoC: ${ORANGE}${EXPLOIT_DETECTED} ${EXP} / ${POC_DETECTED} ${POC}${NC}")")"
      else
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}")")"
      fi
    done
  fi

  # 输出同时通过符号和编译两种机制验证的高危CVE
  if [[ "${#lCVE_VERIFIED_OVERLAP_CRITICAL_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: ${ORANGE}${#lCVE_VERIFIED_OVERLAP_CRITICAL_ARR[@]}${GREEN} (both mechanisms overlap)"
    for lCVE_VERIFIED_OVERLAP_CRITICAL in "${lCVE_VERIFIED_OVERLAP_CRITICAL_ARR[@]}"; do
      lCVE_CRITICAL=$(echo "${lCVE_VERIFIED_OVERLAP_CRITICAL}" | cut -d\; -f3)
      lCVSS2_CRITICAL=$(echo "${lCVE_VERIFIED_OVERLAP_CRITICAL}" | cut -d\; -f4)
      lCVSS3_CRITICAL=$(echo "${lCVE_VERIFIED_OVERLAP_CRITICAL}" | cut -d\; -f5)
      # disabled because it is too slow
      # identify_exploits "${lCVE_CRITICAL}"
      if [[ "${EXPLOIT_DETECTED:-"no"}" == "yes" ]] || [[ "${POC_DETECTED:-"no"}" == "yes" ]]; then
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}\t-\tExploit/PoC: ${ORANGE}${EXPLOIT_DETECTED} ${EXP} / ${POC_DETECTED} ${POC}${NC}")")"
      else
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}")")"
      fi
    done
  fi
  # 记录统计数据
  write_log "[*] Statistics:${lK_VERSION}:${#lALL_KVULNS_ARR[@]}:${lCVE_VERIFIED_SYMBOLS}:${lCVE_VERIFIED_COMPILED}"
}

# ==========================================================================================
# identify_exploits - 识别CVE是否有公开的Exploit/PoC
#
# 功能:
#   在多个数据库中搜索与CVE相关的已知漏洞利用代码
#
# 数据来源:
#   - Exploit-DB (通过cve_searchsploit工具)
#   - Metasploit Framework数据库
#   - 已知漏洞利用CSV
#   - Snyk PoC结果
#   - PacketStorm PoC结果
#
# 参数:
#   $1 - lCVE_VALUE: CVE编号
#
# 全局变量:
#   EXPLOIT_DETECTED: 是否发现Exploit (yes/no)
#   POC_DETECTED: 是否发现PoC (yes/no)
#   EXP: Exploit来源标识 (EDB/MSF/KNOWN)
#   POC: PoC来源标识 (SNYK/PS)
# ==========================================================================================
identify_exploits() {
  local lCVE_VALUE="${1:-}"
  export EXPLOIT_DETECTED="no"
  export POC_DETECTED="no"
  export POC=""
  export EXP=""

  # 检查Exploit-DB
  if command -v cve_searchsploit >/dev/null; then
    if cve_searchsploit "${lCVE_VALUE}" 2>/dev/null | grep -q "Exploit DB Id:"; then
      EXPLOIT_DETECTED="yes"
      EXP="(EDB)"
    fi
  fi

  # 检查Metasploit数据库
  if [[ -f "${MSF_DB_PATH}" ]]; then
    if grep -q -E "${lCVE_VALUE}"$ "${MSF_DB_PATH}"; then
      EXPLOIT_DETECTED="yes"
      EXP="${EXP}(MSF)"
    fi
  fi

  # 检查已知漏洞利用CSV
  if [[ -f "${KNOWN_EXP_CSV}" ]]; then
    if grep -q \""${lCVE_VALUE}"\", "${KNOWN_EXP_CSV}"; then
      EXPLOIT_DETECTED="yes"
      EXP="${EXP}(KNOWN)"
    fi
  fi

  # 检查Snyk PoC
  if [[ -f "${CONFIG_DIR}/Snyk_PoC_results.csv" ]]; then
    if grep -q -E "^${lCVE_VALUE};" "${CONFIG_DIR}/Snyk_PoC_results.csv"; then
      POC_DETECTED="yes"
      POC="${POC}(SNYK)"
    fi
  fi

  # 检查PacketStorm PoC
  if [[ -f "${CONFIG_DIR}/PS_PoC_results.csv" ]]; then
    if grep -q -E "^${lCVE_VALUE};" "${CONFIG_DIR}/PS_PoC_results.csv"; then
      POC_DETECTED="yes"
      POC="${POC}(PS)"
    fi
  fi
}

# ==========================================================================================
# get_kernel_version_csv_data_s24 - 从S24模块CSV提取内核版本
#
# 功能:
#   读取S24模块生成的内核识别结果CSV
#   提取其中的内核版本号列表
#
# 参数:
#   $1 - lS24_CSV_LOG: S24模块的CSV日志文件路径
#
# 全局变量:
#   K_VERSIONS_ARR: 提取到的内核版本数组
#
# 注意:
#   当前版本只支持一个内核版本
#   如果检测到多个版本,取排序后的第一个
# ==========================================================================================
get_kernel_version_csv_data_s24() {
  local lS24_CSV_LOG="${1:-}"

  if ! [[ -f "${lS24_CSV_LOG}" ]];then
    print_output "[-] No EMBA log found ..."
    return
  fi

  export K_VERSIONS_ARR=()

  # 从CSV第2字段提取内核版本
  # 跳过表头(tail -n +2)
  # 过滤掉NA值
  # 去重排序
  # currently we only support one kernel version
  # if we detect multiple kernel versions we only process the first one after sorting
  mapfile -t K_VERSIONS_ARR < <(cut -d\; -f2 "${lS24_CSV_LOG}" | tail -n +2 | grep -v "NA" | sort -u)
}
