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
# Credits:   Binarly for support

# Description:  使用 Binarly 的 FwHunt 工具对 UEFI 固件镜像进行漏洞识别和扫描
#               FwHunt 是一种用于检测 UEFI 固件中已知漏洞和恶意代码的扫描引擎
#
# 使用方法:
#   - fwhunt-scan: https://github.com/binarly-io/fwhunt-scan
#     这是 Binarly 开发的命令行扫描工具，支持对固件镜像进行全面分析
#   - FwHunt 规则库: https://github.com/binarly-io/FwHunt
#     包含已知 UEFI 漏洞的检测规则，每条规则对应一个或多个 CVE 漏洞
#
# 工作流程:
#   1. 检查固件是否已通过 UEFI 验证 (UEFI_VERIFIED) 或为支持 UEFI 的 RTOS 系统
#   2. 首先对整个固件进行扫描（性能优化），如果未发现漏洞则逐文件扫描
#   3. 调用 fwhunt_scan_analyzer.py 进行实际扫描
#   4. 解析扫描结果，提取 CVE 编号和 Binarly 漏洞 ID (BRLY-XXXX-XX)
#   5. 生成结构化报告和 CSV 日志
#
# 依赖工具:
#   - fwhunt-scan: Python 编写的固件扫描器
#   - Python 3: 运行环境
#   - EXT_DIR: 外部工具存储目录
#
# 环境变量:
#   - UEFI_VERIFIED: 固件是否已通过 UEFI 格式验证 (1=是, 0=否)
#   - RTOS: 是否为实时操作系统固件
#   - UEFI_DETECTED: 是否检测到 UEFI 组件
#   - FIRMWARE_PATH_BAK: 原始固件文件路径
#   - P99_CSV_LOG: 固件文件分析结果的 CSV 日志
#   - LOG_PATH_MODULE: 模块输出日志目录
#   - THREADED: 是否启用多线程模式
#   - MAX_MOD_THREADS: 最大并行线程数
#   - TOTAL_MEMORY: 系统总内存（用于内存限制）

# ====================================================================================================
# 函数: S02_UEFI_FwHunt
# 功能: UEFI 固件漏洞扫描主函数
# 说明: 使用 Binarly FwHunt 工具对固件镜像进行漏洞检测
#
# 处理流程:
#   1. 初始化模块日志和标题
#   2. 检查目标固件是否为有效的 UEFI 固件（或支持 UEFI 的 RTOS）
#   3. 首先对整个固件进行全局扫描（性能优化策略）
#   4. 如果全局扫描未发现漏洞，则遍历提取的文件逐个扫描
#   5. 等待所有并行扫描任务完成
#   6. 调用 fwhunter_logging 处理和汇总结果
#   7. 记录模块结束状态
#
# 参数: 无（直接使用全局环境变量）
#
# 全局变量:
#   - UEFI_VERIFIED: UEFI 固件验证状态
#   - RTOS: 实时操作系统标识
#   - UEFI_DETECTED: UEFI 检测状态
#   - FIRMWARE_PATH_BAK: 原始固件路径
#   - P99_CSV_LOG: 固件文件分析日志
#   - FWHUNTER_RESULTS_ARR: 存储扫描结果数组
# ====================================================================================================
S02_UEFI_FwHunt() {
  # 初始化模块日志记录器，使用函数名作为日志标识
  module_log_init "${FUNCNAME[0]}"
  # 输出模块标题，使用 Binarly 品牌名称
  module_title "Binarly UEFI FwHunt analyzer"
  # 模块预报告，准备输出基础信息
  pre_module_reporter "${FUNCNAME[0]}"

  # 局部变量声明
  local lNEG_LOG=0                           # 负向日志标记（发现漏洞时设为1）
  local lWAIT_PIDS_S02_ARR=()                # 存储后台进程的 PID 数组
  # shellcheck disable=SC2153
  local lMAX_MOD_THREADS=$((MAX_MOD_THREADS/2))  # 最大并行线程数（取全局线程数的一半）
  local lEXTRACTED_FILE=""                   # 当前处理的提取文件路径

  # ==================================================================================================
  # 条件检查: 只有在以下任一条件满足时才执行扫描:
  #   - UEFI_VERIFIED=1: 固件已通过 UEFI 格式验证
  #   - RTOS=1 且 UEFI_DETECTED=1: 实时操作系统固件中检测到 UEFI 组件
  # ==================================================================================================
  if [[ "${UEFI_VERIFIED}" -eq 1 ]] || { [[ "${RTOS}" -eq 1 ]] && [[ "${UEFI_DETECTED}" -eq 1 ]]; }; then
    # 输出扫描开始提示信息
    print_output "[*] Starting FwHunter UEFI firmware vulnerability detection"

    # ================================================================================================
    # 步骤1: 首先对整个固件进行全局扫描
    # 原因: 为了性能优化，先检查整个固件镜像是否有漏洞
    #       如果发现漏洞，就无需逐个文件扫描，节省时间
    # ================================================================================================
    fwhunter "${FIRMWARE_PATH_BAK}"

    # ================================================================================================
    # 步骤2: 检查全局扫描结果
    #       如果没有发现任何 FwHunt 规则匹配，则遍历提取的文件逐个扫描
    #       grep -c "FwHunt rule" 统计每条日志中匹配 FwHunt 规则的次数
    # ================================================================================================
    if [[ $(grep -c "FwHunt rule" "${LOG_PATH_MODULE}""/fwhunt_scan_"* | cut -d: -f2 | awk '{ SUM += $1} END { print SUM }' || true) -eq 0 ]]; then
      # ==============================================================================================
      # 步骤3: 逐文件扫描模式
      #       从 P99_CSV_LOG 读取文件列表，排除 ASCII text 和 Unicode text 类型文件
      #       （这些文本文件不是有效的 UEFI 固件组件）
      # ==============================================================================================
      while read -r lFILE_DETAILS; do
        # 从文件详情中提取文件路径（CSV 格式: 序号;文件路径;其他信息）
        lEXTRACTED_FILE=$(echo "${lFILE_DETAILS}" | cut -d ';' -f2)

        # 根据是否启用多线程选择执行方式
        if [[ ${THREADED} -eq 1 ]]; then
          # 多线程模式: 后台运行 fwhunter 扫描
          fwhunter "${lEXTRACTED_FILE}" &
          local lTMP_PID="$!"                              # 获取后台任务的 PID
          store_kill_pids "${lTMP_PID}"                    # 注册到进程管理队列
          lWAIT_PIDS_S02_ARR+=( "${lTMP_PID}" )            # 添加到 PID 数组
          # 限制最大并行数，防止同时启动过多进程
          max_pids_protection "${lMAX_MOD_THREADS}" lWAIT_PIDS_S02_ARR
        else
          # 单线程模式: 同步执行扫描
          fwhunter "${lEXTRACTED_FILE}"
        fi
      # 过滤掉文本文件，只保留可能的二进制固件文件
      done < <(grep -v "ASCII text\|Unicode text" "${P99_CSV_LOG}" || true)
    fi
  fi

  # ==================================================================================================
  # 步骤4: 等待所有后台扫描任务完成
  #        只有在多线程模式下才需要等待
  # ==================================================================================================
  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S02_ARR[@]}"

  # ==================================================================================================
  # 步骤5: 处理和汇总所有扫描结果
  #        解析日志文件，提取 CVE 编号和 Binarly ID
  # ==================================================================================================
  fwhunter_logging

  # ==================================================================================================
  # 步骤6: 确定模块日志状态
  #        如果发现任何漏洞（结果数组非空），则设置 lNEG_LOG=1
  # ==================================================================================================
  [[ "${#FWHUNTER_RESULTS_ARR[@]}" -gt 0 ]] && lNEG_LOG=1

  # 记录模块结束日志
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

# ====================================================================================================
# 函数: fwhunter
# 功能: 对指定文件运行 FwHunt 漏洞扫描器
# 说明: 调用 Binarly 的 fwhunt-scan 工具对 UEFI 固件进行漏洞检测
#
# 参数:
#   $1 - lFWHUNTER_CHECK_FILE: 要扫描的文件路径（固件文件或提取的二进制文件）
#
# 工作流程:
#   1. 提取文件名并处理可能的命名冲突
#   2. 设置内存限制（使用系统 80% 内存）
#   3. 调用 fwhunt_scan_analyzer.py 执行扫描
#   4. 将输出同时显示和记录到日志文件
#   5. 删除空的扫描结果文件（只有一行日志的无效结果）
#
# 依赖:
#   - fwhunt_scan_analyzer.py: FwHunt 主扫描程序
#   - EXT_DIR/fwhunt-scan/rules/: 漏洞检测规则库目录
#
# 超时设置: 600 秒（10 分钟），超时或被中断时保留已扫描的内容
# ====================================================================================================
fwhunter() {
  # 参数处理：获取要扫描的文件路径，如果未提供则为空字符串
  local lFWHUNTER_CHECK_FILE="${1:-}"
  local lFWHUNTER_CHECK_FILE_NAME=""    # 用于日志文件名的基础名
  # 计算内存限制：使用系统总内存的 80%，单位为 KB
  # ulimit -Sv 用于限制shell进程的虚拟内存大小
  local lMEM_LIMIT=$(( "${TOTAL_MEMORY}"*80/100 ))

  # 提取文件名（不含路径）
  lFWHUNTER_CHECK_FILE_NAME=$(basename "${lFWHUNTER_CHECK_FILE}")

  # ==================================================================================================
  # 处理文件名冲突:
  #   如果已存在同名的日志文件，则在文件名后添加随机数后缀
  #   这确保每次扫描都有独立的日志文件
  # ==================================================================================================
  while [[ -f "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt" ]]; do
    lFWHUNTER_CHECK_FILE_NAME="${lFWHUNTER_CHECK_FILE_NAME}_${RANDOM}"
  done

  # 输出扫描开始信息，同时写入指定日志文件
  # tee -a 追加模式将输出同时显示和写入文件
  print_output "[*] Running FwHunt on ${ORANGE}${lFWHUNTER_CHECK_FILE}${NC}" "" "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt"

  # ==================================================================================================
  # 设置内存限制:
  #   FwHunt 扫描可能消耗大量内存，限制为系统内存的 80%
  #   防止单个扫描任务耗尽系统资源
  # ==================================================================================================
  ulimit -Sv "${lMEM_LIMIT}"

  # 写入日志文件
  write_log "[*] Running FwHunt on ${ORANGE}${lFWHUNTER_CHECK_FILE}${NC}" "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt"

  # ==================================================================================================
  # 执行 FwHunt 扫描:
  #   使用 timeout 命令设置 600 秒超时
  #   --preserve-status: 保持退出状态即使被信号中断
  #   --signal SIGINT: 优雅终止（允许清理工作）
  #   使用 Python 3 运行扫描器
  #   --rules_dir: 指定规则库目录
  #   || true: 忽略扫描错误（如超时或扫描失败），继续执行
  # ==================================================================================================
  timeout --preserve-status --signal SIGINT 600 python3 "${EXT_DIR}"/fwhunt-scan/fwhunt_scan_analyzer.py scan-firmware "${lFWHUNTER_CHECK_FILE}" --rules_dir "${EXT_DIR}"/fwhunt-scan/rules/ | tee -a "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt" || true

  # 扫描完成后恢复内存限制为无限
  ulimit -Sv unlimited

  # ==================================================================================================
  # 清理空日志文件:
  #   如果日志文件只有一行（通常是初始日志行），说明扫描没有产生有效结果
  #   删除这些空文件以保持日志目录整洁
  # ==================================================================================================
  # delete empty log files
  if [[ $(wc -l < "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt") -eq 1 ]]; then
    rm "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt" || true
  fi
}

# ====================================================================================================
# 函数: fwhunter_logging
# 功能: 解析 FwHunt 扫描结果并生成结构化报告
# 说明: 处理所有扫描日志文件，提取漏洞信息并生成用户友好的输出
#
# 处理流程:
#   1. 查找所有包含"FwHunt rule has been triggered"的日志文件
#   2. 解析每个匹配结果，提取:
#      - Binarly 漏洞 ID (格式: BRLY-XXXX-XX)
#      - CVE 编号 (格式: CVE-YYYY-NNNNN)
#      - 触发漏洞的二进制文件名
#   3. 从规则文件中提取关联的 CVE 信息
#   4. 生成终端输出和 CSV 日志
#   5. 统计并显示发现的漏洞总数
#
# 漏洞信息来源:
#   - FwHunt 扫描日志: 包含实际触发规则的结果
#   - 规则文件: 存储在 EXT_DIR/fwhunt-scan/rules/ 目录
#     每个规则文件命名格式: BRLY-XXXX-XX*.yaml
#     规则文件中包含 "CVE number:" 字段列出关联的 CVE
#
# 全局变量:
#   - FWHUNTER_RESULTS_ARR: 存储所有扫描结果的数组（导出供外部使用）
#   - LOG_FILE: 主日志文件路径
#   - LOG_PATH_MODULE: 模块日志目录
#
# 输出格式:
#   CSV 日志字段: BINARY, VERSION, CVE identifier, CVSS rating, BINARLY ID
# ====================================================================================================
fwhunter_logging() {
  # 初始化结果数组（导出供其他模块使用）
  export FWHUNTER_RESULTS_ARR=()

  # ==================================================================================================
  # 局部变量声明:
  #   - lFWHUNTER_RESULT: 单条扫描结果字符串
  #   - lFWHUNTER_RESULT_FILE: 结果对应的日志文件路径
  #   - lFWHUNTER_BINARLY_ID: Binarly 漏洞 ID (如 BRLY-2024-001)
  #   - lFWHUNTER_CVE_ID: CVE 漏洞编号
  #   - lBINARLY_ID_FILE: 规则文件路径
  #   - lFWHUNTER_BINARLY_ID_FILES_ARR: 匹配的规则文件数组
  #   - lCVE_RESULTS_BINARLY_ARR: 从规则文件提取的 CVE 列表
  #   - lFWHUNTER_CVEs_ARR: 全局 CVE 统计数组
  #   - lFWHUNTER_BINARY_MATCH_ARR: 触发漏洞的二进制文件列表
  # ==================================================================================================
  local lFWHUNTER_RESULT=""
  local lFWHUNTER_RESULT_FILE=""
  local lFWHUNTER_BINARLY_ID=""
  local lFWHUNTER_CVE_ID=""
  local lBINARLY_ID_FILE=""
  local lFWHUNTER_BINARLY_ID_FILES_ARR=()
  local lCVE_RESULTS_BINARLY_ARR=()
  local lFWHUNTER_CVEs_ARR=()
  local lBINARLY_CVE=""
  local lBINARLY_ID_CVE=""
  local lCVE_RESULTS_BINARLY_ARR_=()
  local lFWHUNTER_BINARY_MATCH_ARR=()
  local lFWHUNTER_BINARY_MATCH=""
  local lFWHUNTER_BINARLY_IDs_ARR=()

  # ==================================================================================================
  # 步骤1: 查找所有扫描结果
  #        使用 find + xargs 并行搜索 (-P 16) 包含 "FwHunt rule has been triggered" 的日志
  #        mapfile 将结果存储到数组中
  #        格式: "日志文件路径:匹配的行内容"
  # ==================================================================================================
  mapfile -t FWHUNTER_RESULTS_ARR < <(find "${LOG_PATH_MODULE}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep -H "Scanner result.*FwHunt rule has been triggered" "%" || true')

  # 如果没有发现任何扫描结果，直接返回
  if ! [[ "${#FWHUNTER_RESULTS_ARR[@]}" -gt 0 ]]; then
    return
  fi

  # 输出子模块标题
  print_ln
  sub_module_title "FwHunt UEFI vulnerability details"
  # 写入 CSV 表头: 二进制名, 版本, CVE ID, CVSS评分, Binarly ID
  write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "BINARLY ID"

  # ==================================================================================================
  # 步骤2: 遍历每个扫描结果进行处理
  # ==================================================================================================
  for lFWHUNTER_RESULT in "${FWHUNTER_RESULTS_ARR[@]}"; do
    local lCVE_RESULTS_BINARLY_ARR=()

    # 从结果字符串中分离文件路径和匹配内容
    # 格式: "path/to/log.txt:Scanner result ... triggered"
    lFWHUNTER_RESULT_FILE=$(echo "${lFWHUNTER_RESULT}" | cut -d: -f1)
    lFWHUNTER_RESULT=$(echo "${lFWHUNTER_RESULT}" | cut -d: -f2-)

    # ================================================================================================
    # 步骤3: 提取漏洞标识符
    #        使用正则表达式匹配:
    #        - BRLY-[0-9]+-[0-9]+: Binarly 漏洞ID格式
    #        - CVE-[0-9]+-[0-9]+: 标准CVE编号格式
    #        sort -u: 去重排序
    # ================================================================================================
    lFWHUNTER_BINARLY_ID=$(echo "${lFWHUNTER_RESULT}" | grep -E -o "BRLY-[0-9]+-[0-9]+" | sort -u || true)
    lFWHUNTER_CVE_ID=$(echo "${lFWHUNTER_RESULT}" | grep -E -o "CVE-[0-9]+-[0-9]+" | sort -u || true)
    # lCVE_RESULTS_BINARLY_ARR+=("${lFWHUNTER_CVE_ID}")

    # ================================================================================================
    # 步骤4: 从规则文件提取关联的 CVE 信息
    #        如果发现 Binarly ID，在规则库中查找对应的规则文件
    #        规则文件格式: BRLY-XXXX-XX*.yaml
    #        从规则文件中解析 "CVE number:" 字段获取关联的 CVE 列表
    # ================================================================================================
    if [[ -n "${lFWHUNTER_BINARLY_ID}" ]]; then
      # 查找匹配的规则文件（不区分大小写 -iname）
      mapfile -t lFWHUNTER_BINARLY_ID_FILES_ARR < <(find "${EXT_DIR}"/fwhunt-scan/rules -iname "${lFWHUNTER_BINARLY_ID}*")

      for lBINARLY_ID_FILE in "${lFWHUNTER_BINARLY_ID_FILES_ARR[@]}"; do
        [[ -z "${lBINARLY_ID_FILE}" ]] && continue
        print_output "[*] Testing ${lBINARLY_ID_FILE} for CVEs"
        # ============================================================================================
        # 解析规则文件中的 CVE 信息:
        #   grep "CVE number:" 查找 CVE 字段
        #   cut -d: -f2 取冒号后的内容（可能有多个CVE，用逗号分隔）
        #   tr ',' '\n' 将逗号分隔转换为换行
        #   awk '{print $1}' 取每行的第一个词（CVE编号）
        # ============================================================================================
        # extract possible CVE information from the binarly scan rule:
        mapfile -t lCVE_RESULTS_BINARLY_ARR_ < <(grep "CVE number:" "${lBINARLY_ID_FILE}" 2>/dev/null | cut -d: -f2 | tr ',' '\n' | awk '{print $1}' || true)
        lCVE_RESULTS_BINARLY_ARR+=("${lCVE_RESULTS_BINARLY_ARR_[@]}")
      done
    fi

    # ================================================================================================
    # 步骤5: 获取触发漏洞的二进制文件名
    #        从原始日志文件中查找 "Running FwHunt on" 行
    #        提取文件名并去重
    # ================================================================================================
    mapfile -t lFWHUNTER_BINARY_MATCH_ARR < <(basename "$(grep "Running FwHunt on" "${lFWHUNTER_RESULT_FILE}" | cut -d\  -f5-)" | sort -u || true)

    # ================================================================================================
    # 步骤6: 生成漏洞报告
    #        根据是否有 CVE 信息采用不同格式输出:
    #        - 有 CVE 信息: 详细列出每个 CVE 和二进制文件的组合
    #        - 无 CVE 信息: 只显示 Binarly ID 和二进制文件
    #        同时写入 CSV 日志文件
    # ================================================================================================
    if [[ "${lFWHUNTER_RESULT}" == *"rule has been triggered and threat detected"* ]]; then
      # 分支A: 有 CVE 详细信息
      if [[ "${#lCVE_RESULTS_BINARLY_ARR[@]}" -gt 0 ]]; then
        for lBINARLY_ID_CVE in "${lCVE_RESULTS_BINARLY_ARR[@]}"; do
          for lFWHUNTER_BINARY_MATCH in "${lFWHUNTER_BINARY_MATCH_ARR[@]}"; do
            # if we have CVE details we include it into our reporting
            # 输出带链接的漏洞信息（链接到 Binarly 官方漏洞公告）
            print_output "[+] ${lFWHUNTER_BINARY_MATCH} ${ORANGE}:${GREEN} ${lFWHUNTER_RESULT}${GREEN}" "" "https://binarly.io/advisories/${lFWHUNTER_BINARLY_ID}"
            # 输出 CVE 编号（带缩进格式）
            print_output "$(indent "${GREEN}CVE: ${ORANGE}${lBINARLY_ID_CVE}${NC}")"
            # 写入 CSV 日志: 二进制名, 版本(未知), CVE ID, CVSS评分(未知), Binarly ID
            write_csv_log "${lFWHUNTER_BINARY_MATCH}" "unknown" "${lBINARLY_ID_CVE}" "unknown" "${lFWHUNTER_BINARLY_ID}"
          done
        done
      else
        # 分支B: 无 CVE 详细信息（使用从日志中提取的 CVE，可能为空）
        for lFWHUNTER_BINARY_MATCH in "${lFWHUNTER_BINARY_MATCH_ARR[@]}"; do
          # if we do not have CVE details we can't include it into our reporting
          print_output "[+] ${lFWHUNTER_BINARY_MATCH} ${ORANGE}:${GREEN} ${lFWHUNTER_RESULT}${NC}" "" "https://binarly.io/advisories/${lFWHUNTER_BINARLY_ID}"
          # CVE 字段使用 NA（不可用）或从日志提取的 ID
          write_csv_log "${lFWHUNTER_BINARY_MATCH}" "unknown" "${lFWHUNTER_CVE_ID:-NA}" "unknown" "${lFWHUNTER_BINARLY_ID}"
        done
      fi
    fi
  done

  # ==================================================================================================
  # 步骤7: 全局统计
  #        从主日志文件和模块日志中收集所有 CVE 和 Binarly ID
  # ==================================================================================================
  # 提取主日志中所有唯一的 CVE 编号
  mapfile -t lFWHUNTER_CVEs_ARR < <(grep -E -o "CVE-[0-9]{4}-[0-9]+" "${LOG_FILE}" | sort -u || true)
  # 提取模块日志中所有唯一的 Binarly ID
  # 使用 sed 提取 BRLY- 开头到 .variant: 之前的部分（去除变体信息）
  mapfile -t lFWHUNTER_BINARLY_IDs_ARR < <(grep "FwHunt rule has been triggered and threat detected" "${LOG_PATH_MODULE}"/* | grep "BRLY-" | sed 's/.*BRLY-/BRLY-/' | sed 's/\ .variant:\ .*//g' | sort -u || true)

  # ==================================================================================================
  # 步骤8: 输出统计摘要
  # ==================================================================================================
  print_ln

  # 输出发现的有效 CVE 数量
  if [[ "${#lFWHUNTER_CVEs_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Detected ${ORANGE}${#lFWHUNTER_CVEs_ARR[@]}${GREEN} firmware issues with valid CVE identifier in UEFI firmware:"
    for lBINARLY_CVE in "${lFWHUNTER_CVEs_ARR[@]}"; do
      print_output "$(indent "$(orange "${lBINARLY_CVE}")")"
    done
  fi

  # 输出发现的 Binarly ID 数量
  if [[ "${#lFWHUNTER_BINARLY_IDs_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Detected ${ORANGE}${#lFWHUNTER_BINARLY_IDs_ARR[@]}${GREEN} firmware issues with valid binarly id in UEFI firmware:"
    for BINARLY_ID in "${lFWHUNTER_BINARLY_IDs_ARR[@]}"; do
      print_output "$(indent "$(orange "${BINARLY_ID}")")"
    done
  fi
  print_ln

  # ==================================================================================================
  # 步骤9: 写入统计信息到日志
  #        格式: CVE数量:Binarly ID数量
  # ==================================================================================================
  write_log ""
  write_log "[*] Statistics:${#lFWHUNTER_CVEs_ARR[@]}:${#lFWHUNTER_BINARLY_IDs_ARR[@]}"
}
