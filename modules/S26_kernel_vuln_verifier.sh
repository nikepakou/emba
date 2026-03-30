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
  export KERNEL_SOURCE_AVAILABLE=0      # 内核源码是否可用标志

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
    fi

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
    KERNEL_SOURCE_AVAILABLE=0
    while ! [[ -f "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" ]]; do
      print_output "[*] Waiting for kernel sources ..." "no_log"
      ((lWAIT_CNT+=1))
      # 超时或下载失败则进入降级模式
      if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... switching to symbol-based verification mode"
        KERNEL_SOURCE_AVAILABLE=0
        break
      fi
      sleep 5
    done

    # 如果有源码文件,测试压缩包完整性
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -ne 0 ]] && [[ -f "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" ]]; then
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
          print_output "[-] No valid kernel source file available ... switching to symbol-based verification mode"
          KERNEL_SOURCE_AVAILABLE=0
          break
        fi
        sleep 5
      done
      
      # 如果通过了完整性测试,标记为可用
      if [[ "${lWAIT_CNT}" -le 60 ]] && ! [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        KERNEL_SOURCE_AVAILABLE=1
      fi
    fi

    # ============================================================
    # 步骤4: 根据内核源码可用性选择执行模式
    # ============================================================
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -eq 1 ]]; then
      print_output "[*] Kernel sources for version ${ORANGE}${lK_VERSION}${NC} available"
      write_link "${LOG_DIR}/kernel_downloader.log"
    else
      print_output "[*] Kernel sources for version ${ORANGE}${lK_VERSION}${NC} not available - using degraded verification mode"
    fi

    # ============================================================
    # 步骤5: 解压内核源码(仅在源码可用时)
    # ============================================================
    local lKERNEL_DIR=""
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -eq 1 ]]; then
      lKERNEL_DIR="${LOG_PATH_MODULE}/linux-${lK_VERSION_KORG}"
      [[ -d "${lKERNEL_DIR}" ]] && rm -rf "${lKERNEL_DIR}"
      if ! [[ -d "${lKERNEL_DIR}" ]] && [[ "$(file "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz")" == *"gzip compressed data"* ]]; then
        print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} extraction ... "
        tar -xzf "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" -C "${LOG_PATH_MODULE}"
      fi
    fi

    # ============================================================
    # 步骤6: 提取内核符号(两种模式都需要)
    # 从内核ELF文件和内核模块(.ko)中提取符号
    # ============================================================
    sub_module_title "Identify kernel symbols ..."
    # 使用readelf提取FUNC和OBJECT类型的符号
    readelf -W -s "${KERNEL_ELF_PATH}" | grep "FUNC\|OBJECT" | sed 's/.*FUNC//' | sed 's/.*OBJECT//' | awk '{print $4}' | \
      sed 's/\[\.\.\.\]//' > "${LOG_PATH_MODULE}"/symbols.txt || true
    export SYMBOLS_CNT=0
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
      find "${LOG_DIR}/firmware" -name "*.ko" -print0|xargs -r -0 -P 16 -I % sh -c 'readelf -W -a "%" | grep FUNC | sed "s/.*FUNC//" | awk "{print \$4}" | sed "s/\[\.\.\.\]//"' >> "${LOG_PATH_MODULE}"/symbols.txt || true
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
    # 步骤7: 根据模式执行不同的CVE检测和验证流程
    # ============================================================
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -eq 1 ]]; then
      # ============================================================
      # 正常模式: 源码可用,执行完整的CVE检测和验证
      # ============================================================
      print_output "[*] Running in normal mode with kernel source verification"
      
      # 使用cve-bin-tool检测CVE
      print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} CVE detection ... "
      if ! grep -q "cve-bin-tool database preparation finished" "${TMP_DIR}/tmp_state_data.log"; then
        print_error "[-] cve-bin-tool database not prepared - cve analysis probably not working"
      fi
      cve_bin_tool_threader "${lBOM_REF}" "${lK_VERSION}" "${lORIG_SOURCE:-kernel_verification}" lVENDOR_ARR lPRODUCT_ARR

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

      # 编译内核(dry-run)获取使用的源文件
      if [[ -f "${KERNEL_CONFIG_PATH}" ]] && [[ -d "${lKERNEL_DIR}" ]]; then
        compile_kernel "${KERNEL_CONFIG_PATH}" "${lKERNEL_DIR}" "${ORIG_K_ARCH}"
      fi

      # 并行验证每个CVE漏洞
      sub_module_title "Linux kernel vulnerability verification"

      print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC}" "" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      print_ln

      local lVULN=""
      for lVULN in "${lALL_KVULNS_ARR[@]}"; do
        vuln_checker_threader "${lVULN}" "${lKERNEL_DIR}" &
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
    else
      # ============================================================
      # 降级模式: 源码不可用,仅基于符号进行CVE过滤
      # ============================================================
      print_output "[*] Running in degraded mode without kernel source - using symbol-based CVE filtering"
      
      # 使用cve-bin-tool检测CVE
      print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} CVE detection ... "
      if ! grep -q "cve-bin-tool database preparation finished" "${TMP_DIR}/tmp_state_data.log"; then
        print_error "[-] cve-bin-tool database not prepared - cve analysis probably not working"
      fi
      cve_bin_tool_threader "${lBOM_REF}" "${lK_VERSION}" "${lORIG_SOURCE:-kernel_verification}" lVENDOR_ARR lPRODUCT_ARR

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
      print_output "[*] Filtering CVEs based on kernel symbols ..."

      # 基于符号过滤CVE
      sub_module_title "Linux kernel vulnerability filtering (degraded mode)"

      print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC} (symbol-based filtering)" "" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      print_ln

      local lVULN=""
      for lVULN in "${lALL_KVULNS_ARR[@]}"; do
        # 在降级模式下,使用符号名验证器
        vuln_checker_threader_degraded "${lVULN}" &
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
    fi
  done

  # ============================================================
  # 步骤8: 更新漏洞汇总报告,添加已验证的CVE信息
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
          lkVERSION=${lkVERSION//\ /}
          if grep -q "${lkVERSION}" "${LOG_PATH_MODULE}/vuln_summary_new.txt"; then
            continue
          fi
          echo "${lVULN_SUMMARY_ENTRY}" >> "${LOG_PATH_MODULE}/vuln_summary_new.txt"
        done < "${LOG_PATH_MODULE}/vuln_summary.txt"
        mv "${LOG_PATH_MODULE}/vuln_summary_new.txt" "${LOG_PATH_MODULE}/vuln_summary.txt" || true
      fi
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${VULN_CNT}"
}

# ==========================================================================================
# extract_kernel_arch - 从内核ELF文件提取架构信息
#
# 功能:
#   使用readelf分析内核ELF文件,识别目标架构
#   支持多种架构: ARM, x86, MIPS, PowerPC, RISC-V等
#
# 参数:
#   $1 - 内核ELF文件路径
#
# 输出:
#   设置全局变量 ORIG_K_ARCH
# ==========================================================================================
extract_kernel_arch() {
  local lKERNEL_ELF="${1:-}"
  # 使用readelf获取机器类型
  local lK_ARCH=""
  lK_ARCH=$(readelf -h "${lKERNEL_ELF}" 2>/dev/null | grep Machine | awk '{print $2}')

  # ARM架构
  if [[ "${lK_ARCH}" == *"ARM"* ]]; then
    ORIG_K_ARCH="arm"
  fi

  # AArch64/ARM64架构
  if [[ "${lK_ARCH}" == *"AArch64"* ]]; then
    ORIG_K_ARCH="arm64"
  fi

  # MIPS架构
  if [[ "${lK_ARCH}" == *"MIPS"* ]]; then
    ORIG_K_ARCH="mips"
  fi

  # RISC-V架构
  if [[ "${lK_ARCH}" == *"RISC-V"* ]]; then
    ORIG_K_ARCH="riscv"
  fi

  # PowerPC架构
  if [[ "${lK_ARCH}" == *"PowerPC"* ]]; then
    ORIG_K_ARCH="powerpc"
  fi

  # SuperH架构
  if [[ "${lK_ARCH}" == *"SuperH"* ]]; then
    ORIG_K_ARCH="sh"
  fi

  # nios2架构
  if [[ "${lK_ARCH}" == *"Altera Nios II"* ]]; then
    ORIG_K_ARCH="nios2"
  fi

  # x86架构
  if [[ "${lK_ARCH}" == *"Intel"* ]]; then
    ORIG_K_ARCH="x86"
  fi

  # 转换为小写并移除空格
  ORIG_K_ARCH="${ORIG_K_ARCH,,}"
  ORIG_K_ARCH="${ORIG_K_ARCH//\ /}"
  print_output "[+] Identified kernel architecture ${ORANGE}${ORIG_K_ARCH}${NC}"
}

# ==========================================================================================
# symbol_verifier - 符号验证函数
#
# 功能:
#   检查CVE中提到的源文件是否使用了内核导出的符号
#   通过匹配EXPORT_SYMBOL和EXPORT_SYMBOL_GPL来验证
#
# 参数:
#   $1 - lCVE: CVE编号
#   $2 - lK_VERSION: 内核版本
#   $3 - lK_PATH: 源文件路径
#   $4 - lCVSS: CVSS评分
#   $5 - lKERNEL_DIR: 内核源码目录
#
# 输出:
#   创建${CVE}_symbol_verified.txt文件记录验证成功的CVE
# ==========================================================================================
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
#   5. 执行make -Bndi获取编译文件列表
#   6. 解析输出提取.c/.h/.S文件
#   7. 去重并保存到日志
#
# 参数:
#   $1 - lCONFIG: 内核配置文件路径
#   $2 - lKERNEL_DIR: 内核源码目录
#   $3 - lARCH: 目标架构
#
# 输出:
#   - kernel-compile-files.log: 所有编译涉及的文件
#   - kernel-compile-files_verified.log: 实际存在的源文件
# ==========================================================================================
compile_kernel() {
  local lCONFIG="${1:-}"
  local lKERNEL_DIR="${2:-}"
  local lARCH="${3:-}"

  # 检查配置文件是否存在
  if ! [[ -f "${lCONFIG}" ]]; then
    print_output "[-] No kernel configuration file available"
    return
  fi

  # 检查内核源码目录是否存在
  if ! [[ -d "${lKERNEL_DIR}" ]]; then
    print_output "[-] No kernel source directory available"
    return
  fi

  # 检查架构目录是否存在
  if ! [[ -d "${lKERNEL_DIR}/arch/${lARCH}" ]]; then
    print_output "[-] Architecture ${ORANGE}${lARCH}${NC} not supported in kernel sources"
    return
  fi

  sub_module_title "Compile kernel - dry run mode"

  print_output "[*] Copy kernel configuration file ${ORANGE}${lCONFIG}${NC} to kernel source directory"
  # 复制配置文件到内核源码目录
  cp "${lCONFIG}" "${lKERNEL_DIR}/.config" || true

  print_output "[*] Update kernel configuration"
  # 更新内核配置,使用默认值填充新选项
  make -C "${lKERNEL_DIR}" ARCH="${lARCH}" olddefconfig 2>/dev/null || true

  print_output "[*] Compile kernel - dry run mode"
  # 使用干跑模式获取编译文件列表
  # -B: 强制重建所有目标
  # -n: 只打印命令,不执行
  # -d: 调试模式,输出详细信息
  # -i: 忽略错误
  # 基于论文: https://arxiv.org/pdf/2209.05217.pdf
  make -C "${lKERNEL_DIR}" ARCH="${lARCH}" -Bndi 2>/dev/null | grep -E "\.c|\.h|\.S" > "${LOG_PATH_MODULE}"/kernel-compile-files.log || true

  print_output "[*] Extract kernel source files from compile log"
  # 从编译日志中提取源文件路径
  # 格式: 文件名:行号 或 完整路径
  sed -r 's/([0-9]+)\s+//' "${LOG_PATH_MODULE}"/kernel-compile-files.log | sed 's/\s+//' | sort -u > "${LOG_PATH_MODULE}"/kernel-compile-files_uniq.log || true

  # 过滤出实际存在的源文件
  while read -r lCOMPILE_FILE; do
    if [[ -f "${lKERNEL_DIR}/${lCOMPILE_FILE}" ]]; then
      echo "${lCOMPILE_FILE}" >> "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log
    fi
  done < "${LOG_PATH_MODULE}"/kernel-compile-files_uniq.log

  # 统计编译涉及的源文件数量
  if [[ -f "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ]]; then
    COMPILE_SOURCE_FILES_VERIFIED=$(wc -l < "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log)
    print_output "[+] Identified ${ORANGE}${COMPILE_SOURCE_FILES_VERIFIED}${GREEN} kernel source files used during compilation"
    write_link "${LOG_PATH_MODULE}/kernel-compile-files_verified.log"
  fi
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
# cve_bin_tool_threader - CVE检测线程函数
#
# 功能:
#   调用cve-bin-tool检测指定内核版本的CVE漏洞
#   生成CSV格式的CVE列表供后续验证使用
#
# 参数:
#   $1 - lBOM_REF: SBOM引用ID
#   $2 - lK_VERSION: 内核版本
#   $3 - lORIG_SOURCE: 来源标识
#   $4 - lVENDOR_ARR: 供应商数组(引用)
#   $5 - lPRODUCT_ARR: 产品数组(引用)
# ==========================================================================================
cve_bin_tool_threader() {
  local lBOM_REF="${1:-}"
  local lK_VERSION="${2:-}"
  local lORIG_SOURCE="${3:-}"
  local -n lVENDOR_ARR=${4}
  local -n lPRODUCT_ARR=${5}

  # 构建cve-bin-tool命令参数
  local lCVE_BIN_TOOL_ARGS=""
  lCVE_BIN_TOOL_ARGS="-a ${lBOM_REF}"
  lCVE_BIN_TOOL_ARGS+=" -v ${lK_VERSION}"
  lCVE_BIN_TOOL_ARGS+=" -s ${lORIG_SOURCE}"
  lCVE_BIN_TOOL_ARGS+=" -o ${LOG_PATH_MODULE}"
  lCVE_BIN_TOOL_ARGS+=" -d ${NVD_DIR}"

  # 添加供应商和产品信息
  for lVENDOR in "${lVENDOR_ARR[@]}"; do
    lCVE_BIN_TOOL_ARGS+=" --vendor ${lVENDOR}"
  done

  for lPRODUCT in "${lPRODUCT_ARR[@]}"; do
    lCVE_BIN_TOOL_ARGS+=" --product ${lPRODUCT}"
  done

  # 执行cve-bin-tool
  print_output "[*] Running cve-bin-tool with args: ${lCVE_BIN_TOOL_ARGS}" "no_log"
  cve-bin-tool ${lCVE_BIN_TOOL_ARGS} > /dev/null 2>&1 || true
}

# ==========================================================================================
# vuln_checker_threader - CVE漏洞检查线程函数(正常模式)
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
#   $2 - lKERNEL_DIR: 内核源码目录
# ==========================================================================================
vuln_checker_threader() {
  local lVULN="${1:-}"
  local lKERNEL_DIR="${2:-}"
  local lK_PATHS_ARR=()
  local lK_PATHS_FILES_TMP_ARR=()
  local lK_PATH=""
  local lCVE=""
  local lCVSS3=""
  local lSUMMARY=""

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

  # 从NVD JSON文件中提取英文描述
  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE%-*}/${lCVE:0:11}"*"xx/${lCVE}.json" 2>/dev/null || true)

  # 从CVE描述中提取内核源文件路径
  mapfile -t lK_PATHS_ARR < <(echo "${lSUMMARY}" | tr ' ' '\n' | sed 's/\\$//' | grep ".*\.[chS]$" | sed -r 's/CVE-[0-9]+-[0-9]+:[0-9].*://' \
    | sed -r 's/CVE-[0-9]+-[0-9]+:null.*://' | sed 's/^(//' | sed 's/)$//' | sed 's/,$//' | sed 's/\.$//' | cut -d: -f1 || true)

  # 对没有完整路径的文件名,在内核源码中查找匹配文件
  for lK_PATH in "${lK_PATHS_ARR[@]}"; do
    if ! [[ "${lK_PATH}" == *"/"* ]]; then
      lOUTx="[*] Found file name ${ORANGE}${lK_PATH}${NC} for ${ORANGE}${lCVE}${NC} without path details ... looking for candidates now"
      print_output "${lOUTx}" "no_log"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      mapfile -t lK_PATHS_FILES_TMP_ARR < <(find "${lKERNEL_DIR}" -name "${lK_PATH}" | sed "s&${lKERNEL_DIR}\/&&")
    fi
    lK_PATHS_ARR+=("${lK_PATHS_FILES_TMP_ARR[@]}")
  done

  # 对每个找到的路径进行验证
  if [[ "${#lK_PATHS_ARR[@]}" -gt 0 ]]; then
    for lK_PATH in "${lK_PATHS_ARR[@]}"; do
      if [[ -f "${lKERNEL_DIR}/${lK_PATH}" ]]; then
        # 检查是否是架构相关路径
        if [[ "${lK_PATH}" == "arch/"* ]]; then
          if [[ "${lK_PATH}" == "arch/${ORIG_K_ARCH}/"* ]]; then
            write_log "lCNT_PATHS_FOUND" "${TMP_DIR}/s25_counting.tmp"
            if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
              symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" "${lKERNEL_DIR}" &
              lWAIT_PIDS_S26_ARR+=( "$!" )
            fi
            if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
              compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" &
              lWAIT_PIDS_S26_ARR+=( "$!" )
            fi
          else
            lOUTx="[-] Vulnerable path for different architecture found for ${ORANGE}${lK_PATH}${NC} - not further processing ${ORANGE}${lCVE}${NC}"
            print_output "${lOUTx}" "no_log"
            write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
            write_log "lCNT_PATHS_FOUND_WRONG_ARCH" "${TMP_DIR}/s25_counting.tmp"
          fi
        else
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
        lOUTx="[-] No source file ${ORANGE}${lK_PATH}${NC} in kernel sources for ${ORANGE}${lCVE}${NC}"
        print_output "${lOUTx}" "no_log"
        write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
        write_log "lCNT_PATHS_NOT_FOUND" "${TMP_DIR}/s25_counting.tmp"
      fi
    done
  else
    lOUTx="[-] No kernel source paths extracted for ${ORANGE}${lCVE}${NC}"
    print_output "${lOUTx}" "no_log"
    write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    write_log "lCNT_NO_PATHS" "${TMP_DIR}/s25_counting.tmp"
  fi

  # 等待所有验证进程完成
  wait_for_pid "${lWAIT_PIDS_S26_ARR[@]}"
}

# ==========================================================================================
# vuln_checker_threader_degraded - CVE漏洞检查线程函数(降级模式)
#
# 功能:
#   在源码不可用的情况下,基于符号名匹配进行CVE过滤
#   从NVD提取CVE相关的函数名,与固件符号表进行匹配
#
# 验证流程:
#   1. 从CVE条目提取CVE编号
#   2. 从NVD数据库获取CVE详细描述
#   3. 尝试从描述中提取受影响的函数名
#   4. 检查函数名是否在固件符号表中
#   5. 记录匹配结果
#
# 参数:
#   $1 - lVULN: CVE漏洞条目(CSV格式)
# ==========================================================================================
vuln_checker_threader_degraded() {
  local lVULN="${1:-}"
  local lCVE=""
  local lCVSS3=""
  local lSUMMARY=""
  local lVULN_FOUND=0

  # 从CSV第4字段提取CVE编号
  lCVE=$(echo "${lVULN}" | cut -d, -f4)
  if ! [[ "${lCVE}" == "CVE-"* ]]; then
    print_output "[-] No CVE identifier extracted for ${lVULN} ..."
    return
  fi

  # 输出进度信息
  local lOUTx="[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#lALL_KVULNS_ARR[@]}${NC} / ${ORANGE}${lCVE}${NC} (degraded mode)"
  print_output "${lOUTx}" "no_log"
  write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"

  # 从CSV第6字段提取CVSSv3评分
  lCVSS3="$(echo "${lVULN}" | cut -d, -f6)"

  # 从NVD JSON文件中提取英文描述
  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE%-*}/${lCVE:0:11}"*"xx/${lCVE}.json" 2>/dev/null || true)

  # 尝试从CVE描述中提取函数名
  # 常见的函数名模式: function_name(), function_name( 等
  local lAFFECTED_FUNCS=()
  mapfile -t lAFFECTED_FUNCS < <(echo "${lSUMMARY}" | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*\s*\(' | sed 's/\s*($//' | sort -u || true)

  # 如果没有提取到函数名,尝试其他模式
  if [[ "${#lAFFECTED_FUNCS[@]}" -eq 0 ]]; then
    # 尝试从描述中提取可能的符号名(大写字母开头的标识符)
    mapfile -t lAFFECTED_FUNCS < <(echo "${lSUMMARY}" | grep -oE '\b[A-Z_][A-Z0-9_]*\b' | sort -u || true)
  fi

  # 检查提取的函数名是否在固件符号表中
  if [[ "${#lAFFECTED_FUNCS[@]}" -gt 0 ]]; then
    for lFUNC in "${lAFFECTED_FUNCS[@]}"; do
      # 跳过常见的非函数标识符
      if [[ "${lFUNC}" == "CVE"* ]] || [[ "${lFUNC}" == "LINUX"* ]] || [[ "${lFUNC}" == "KERNEL"* ]]; then
        continue
      fi

      # 检查函数名是否在符号表中
      if grep -q "^${lFUNC}$" "${LOG_PATH_MODULE}/symbols_uniq.txt"; then
        lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS3}${GREEN}) - function ${ORANGE}${lFUNC}${GREEN} found in kernel symbols (degraded mode)${NC}"
        print_output "${lOUTx}"
        write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
        echo "${lCVE} (${lCVSS3}) - ${lK_VERSION} - symbol verified (degraded) - ${lFUNC}" >> "${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt"
        lVULN_FOUND=1
        break
      fi
    done
  fi

  # 如果通过函数名匹配找到,记录验证结果
  if [[ "${lVULN_FOUND}" -eq 1 ]]; then
    write_log "lCNT_SYMBOL_VERIFIED_DEGRADED" "${TMP_DIR}/s25_counting.tmp"
  else
    lOUTx="[-] ${ORANGE}${lCVE}${NC} - no matching symbols found in kernel (degraded mode)"
    print_output "${lOUTx}" "no_log"
    write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    write_log "lCNT_NO_SYMBOL_MATCH" "${TMP_DIR}/s25_counting.tmp"
  fi
}

# ==========================================================================================
# final_log_kernel_vulns - 生成最终内核漏洞报告
#
# 功能:
#   汇总所有验证结果,生成最终的CSV报告
#   统计已验证和未验证的CVE数量
#
# 参数:
#   $1 - lK_VERSION: 内核版本
#   $@ - lALL_KVULNS_ARR: 所有CVE漏洞数组
# ==========================================================================================
final_log_kernel_vulns() {
  local lK_VERSION="${1:-}"
  shift
  local lALL_KVULNS_ARR=("$@")
  local lVERIFIED_SYMBOL=0
  local lVERIFIED_COMPILE=0
  local lVERIFIED_BOTH=0
  local lNOT_VERIFIED=0
  local lVULN=""
  local lCVE=""

  print_output "[*] Generating final vulnerability report for kernel ${ORANGE}${lK_VERSION}${NC}"

  # 创建CSV报告文件
  echo "kernel_version;cve;cvss;verified_symbol;verified_compile;status" > "${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"

  for lVULN in "${lALL_KVULNS_ARR[@]}"; do
    lCVE=$(echo "${lVULN}" | cut -d, -f4)
    local lCVSS=$(echo "${lVULN}" | cut -d, -f6)
    local lSYMBOL_VERIFIED=0
    local lCOMPILE_VERIFIED=0

    # 检查是否有符号验证
    if [[ -f "${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt" ]]; then
      lSYMBOL_VERIFIED=1
      ((lVERIFIED_SYMBOL++))
    fi

    # 检查是否有编译验证
    if [[ -f "${LOG_PATH_MODULE}/${lCVE}_compiled_verified.txt" ]]; then
      lCOMPILE_VERIFIED=1
      ((lVERIFIED_COMPILE++))
    fi

    # 统计双重验证
    if [[ "${lSYMBOL_VERIFIED}" -eq 1 ]] && [[ "${lCOMPILE_VERIFIED}" -eq 1 ]]; then
      ((lVERIFIED_BOTH++))
    fi

    # 统计未验证
    if [[ "${lSYMBOL_VERIFIED}" -eq 0 ]] && [[ "${lCOMPILE_VERIFIED}" -eq 0 ]]; then
      ((lNOT_VERIFIED++))
    fi

    # 写入CSV
    echo "${lK_VERSION};${lCVE};${lCVSS};${lSYMBOL_VERIFIED};${lCOMPILE_VERIFIED};verified" >> "${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"
  done

  # 输出统计信息
  print_output "[+] Verification statistics for kernel ${ORANGE}${lK_VERSION}${NC}:"
  print_output "    - Symbol verified: ${ORANGE}${lVERIFIED_SYMBOL}${NC}"
  print_output "    - Compile verified: ${ORANGE}${lVERIFIED_COMPILE}${NC}"
  print_output "    - Both verified: ${ORANGE}${lVERIFIED_BOTH}${NC}"
  print_output "    - Not verified: ${ORANGE}${lNOT_VERIFIED}${NC}"
}

# 调用主函数
S26_kernel_vuln_verifier
