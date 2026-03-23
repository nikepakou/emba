#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  固件操作系统和架构识别模块
#               通过字符串特征匹配识别固件中使用的操作系统类型
#               支持识别: VxWorks, eCos, Adonis, Siprotec, uC/OS, Linux, FreeBSD, FreeRTOS, QNX, Android等
#               如果未发现Linux系统，则使用binwalk进行目标架构检测
#
# 工作流程:
#   1. 提取固件字符串信息用于分析
#   2. 并行检测多种操作系统特征
#   3. 验证Linux文件系统是否存在
#   4. 对于RTOS固件，使用binwalk进行架构识别
#
# 预检线程模式:
#   设置 export PRE_THREAD_ENA=1 可启用预检线程模式
#   该模式下模块将以线程化方式运行
#
# 依赖工具:
#   - binwalk: 固件分析工具，用于架构检测 (-Y: 可视化分析, -A: 签名分析, -%: CPU识别)
#   - strings: 提取二进制字符串
#   - cpu_rec.py: binwalk的CPU识别模块

# ====================================================================================================
# 函数: S03_firmware_bin_base_analyzer
# 功能: 固件二进制基础分析主函数
# 说明: 识别固件中使用的操作系统类型和目标CPU架构
#
# 处理流程:
#   1. 初始化模块日志和标题
#   2. 调用 os_identification 进行操作系统识别
#   3. 对于RTOS固件，调用 binary_architecture_detection 进行架构检测（当前禁用）
#   4. 等待所有后台任务完成
#   5. 生成架构检测报告
#   6. 检查是否有识别结果，更新日志状态
#
# 变量说明:
#   - lNEG_LOG: 负向日志标记，有识别结果时设为1
#   - lWAIT_PIDS_S03_ARR: 存储后台进程PID的数组
#   - FIRMWARE_PATH_CP: 复制后的固件路径
#   - FIRMWARE_PATH_BAK: 原始固件路径备份
#   - RTOS: 实时操作系统标识
# ====================================================================================================
S03_firmware_bin_base_analyzer() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware basic analyzer"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lWAIT_PIDS_S03_ARR=()

  # ==================================================================================================
  # 步骤1: 检查提取的固件目录是否存在
  #         如果存在，则进行操作系统识别
  # ==================================================================================================
  if [[ -d "${FIRMWARE_PATH_CP}" ]] ; then
    export OUTPUT_DIR="${FIRMWARE_PATH_CP}"
    if [[ ${THREADED} -eq 1 ]]; then
      # 多线程模式：后台运行操作系统识别
      os_identification &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S03_ARR+=( "${lTMP_PID}" )
    else
      # 单线程模式：同步执行
      os_identification
    fi
  fi

  # ==================================================================================================
  # 步骤2: 对于非Linux固件，进行架构检测
  #         仅当固件为RTOS且未发现Linux文件系统时执行
  #         注意: 当前架构检测机制暂时不可用
  # ==================================================================================================
  # we only do this if we have not found a Linux filesystem
  if [[ -f "${FIRMWARE_PATH_BAK}" ]]; then
    export PRE_ARCH_Y_ARR=()
    export PRE_ARCH_A_ARR=()
    export PRE_ARCH_CPU_REC=""
    if [[ ${RTOS} -eq 1 ]] ; then
      print_output "[*] INFO: S03 Architecture detection mechanism is currently not available"

      # 架构检测代码已注释，未来可能重新启用
      # if [[ ${THREADED} -eq 1 ]]; then
      #  binary_architecture_detection "${FIRMWARE_PATH_BAK}" &
      #  local lTMP_PID="$!"
      #  store_kill_pids "${lTMP_PID}"
      #  lWAIT_PIDS_S03_ARR+=( "${lTMP_PID}" )
      # else
      #  binary_architecture_detection "${FIRMWARE_PATH_BAK}"
      # fi
    fi
  fi

  # ==================================================================================================
  # 步骤3: 等待所有后台任务完成
  # ==================================================================================================
  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S03_ARR[@]}"

  # ==================================================================================================
  # 步骤4: 生成架构检测报告（如果存在架构数据）
  # ==================================================================================================
  [[ -f "${TMP_DIR}"/s03_arch.tmp ]] && binary_architecture_reporter

  # ==================================================================================================
  # 步骤5: 检查是否有识别结果，更新日志状态
  # ==================================================================================================
  if [[ -f "${TMP_DIR}"/s03.tmp ]]; then
    [[ "$(wc -l < "${TMP_DIR}"/s03.tmp)" -gt 0 ]] && lNEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

# ====================================================================================================
# 函数: os_identification
# 功能: 操作系统识别
# 说明: 通过字符串特征匹配识别固件中使用的操作系统类型
#
# 识别的操作系统列表:
#   Linux, FreeBSD, VxWorks/Wind, FreeRTOS, ADONIS, eCos, uC/OS, SIPROTEC, QNX
#   CPU [34]xx (西门子S7-CPU), CP443 (S7-CP443), Sinamics, UEFI, HelenOS, Windows CE, Android
# ====================================================================================================
os_identification() {
  sub_module_title "OS detection"
  local lOS=""
  local lOS_SEARCHER_ARR=()
  export OS_COUNTER_VxWorks=0

  # 初始化输出
  print_output "[*] Initial OS guessing running ..." "no_log" | tr -d "\n"
  write_log "[*] Initial OS guessing:"
  write_csv_log "Guessed OS" "confidential rating" "verified" "Linux root filesystems found"

  # 定义要搜索的操作系统特征字符串数组
  lOS_SEARCHER_ARR=("Linux" "FreeBSD" "VxWorks\|Wind" "FreeRTOS" "ADONIS" "eCos" "uC/OS" "SIPROTEC" "QNX" "CPU\ [34][12][0-9]-[0-9]" "CP443" "Sinamics" "UEFI" "HelenOS" "Windows\ CE" "Android")
  print_dot
  declare -A OS_COUNTER=()
  local lWAIT_PIDS_S03_1_ARR=()

  # 记录Linux根文件系统信息
  if [[ ${#ROOT_PATH[@]} -gt 1 || ${LINUX_PATH_COUNTER} -gt 2 ]] ; then
    safe_echo "${#ROOT_PATH[@]}" >> "${TMP_DIR}"/s03.tmp
    safe_echo "${LINUX_PATH_COUNTER}" >> "${TMP_DIR}"/s03.tmp
  fi

  print_ln
  print_output "$(indent "$(orange "Operating system detection:")")"

  # 提取字符串信息用于分析
  strings "${FIRMWARE_PATH}" 2>/dev/null > "${LOG_PATH_MODULE}/strings_firmware.txt" || true &
  lWAIT_PIDS_S03_1_ARR+=( "${!}" )
  find "${OUTPUT_DIR}" -xdev -type f -print0|xargs -0 -P 16 -I % sh -c 'strings "%" | uniq >> '"${LOG_PATH_MODULE}/all_strings_firmware.txt"' 2> /dev/null' || true &
  lWAIT_PIDS_S03_1_ARR+=( "${!}" )
  wait_for_pid "${lWAIT_PIDS_S03_1_ARR[@]}"

  local lWAIT_PIDS_S03_1_ARR=()

  # 并行检测每种操作系统
  for lOS in "${lOS_SEARCHER_ARR[@]}"; do
    if [[ ${THREADED} -eq 1 ]]; then
      os_detection_thread_per_os "${lOS}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S03_1_ARR+=( "${lTMP_PID}" )
    else
      os_detection_thread_per_os "${lOS}"
    fi
  done

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S03_1_ARR[@]}"

  # 检查是否检测到Android APK
  if grep -q "Identified Android APK package - performing APK checks" "${P02_LOG}"; then
    lOS_="Android APK"
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "NA" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS_}" "NA" "APK verified" "NA"
  fi

  # 清理临时字符串文件
  if [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    rm "${LOG_PATH_MODULE}/strings_firmware.txt" || true
  fi
  if [[ -f "${LOG_PATH_MODULE}/all_strings_firmware.txt" ]]; then
    rm "${LOG_PATH_MODULE}/all_strings_firmware.txt" || true
  fi
}

# ====================================================================================================
# 函数: os_detection_thread_per_os
# 功能: 单个操作系统的检测线程
# 说明: 对特定操作系统进行字符串匹配和可信度评估
#
# 验证规则:
#   - Linux: 匹配>5次且存在根文件系统时为verified
#   - SIPROTEC: 匹配>100次且VxWorks>20时为verified
#   - CP443: 匹配>100次且VxWorks>20时为verified
#   - 其他系统: 匹配>5次即认为检测到
# ====================================================================================================
os_detection_thread_per_os() {
  local lOS="${1:-}"
  local lDETECTED=0
  local lOS_=""

  # 初始化计数器
  OS_COUNTER[${lOS}]=0
  # 从多个来源搜索操作系统特征字符串
  if [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_PATH_MODULE}/strings_firmware.txt" || true)" ))
  fi
  if [[ -f "${LOG_PATH_MODULE}/all_strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_PATH_MODULE}/all_strings_firmware.txt" 2>/dev/null || true)"))
  fi
  if [[ -f "${LOG_DIR}"/p60_firmware_bin_extractor.txt ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_DIR}"/p60_firmware_bin_extractor.txt 2>/dev/null || true)" ))
  fi
  if [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_PATH_MODULE}/strings_firmware.txt" 2>/dev/null || true)" ))
  fi

  # 记录VxWorks计数器供其他系统验证使用
  if [[ ${lOS} == "VxWorks\|Wind" ]]; then
    OS_COUNTER_VxWorks="${OS_COUNTER[${lOS}]}"
  fi
  # 西门子设备特殊检测: 增加"Original Siemens Equipment"特征匹配
  if [[ ${lOS} == *"CPU "* || ${lOS} == "ADONIS" || ${lOS} == "CP443" ]] && [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "Original Siemens Equipment" "${LOG_PATH_MODULE}/strings_firmware.txt" || true)" ))
  fi

  if [[ ${lOS} == "Linux" && ${OS_COUNTER[${lOS}]} -gt 5 && ${#ROOT_PATH[@]} -gt 1 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "${#ROOT_PATH[@]}"
    lDETECTED=1
  elif [[ ${lOS} == "Linux" && ${OS_COUNTER[${lOS}]} -gt 5 && ${LINUX_PATH_COUNTER} -gt 2 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "${#ROOT_PATH[@]}"
    lDETECTED=1
  elif [[ ${lOS} == "Linux" && ${OS_COUNTER[${lOS}]} -gt 5 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "not verified" "${#ROOT_PATH[@]}"
    lDETECTED=1
  fi

  if [[ ${lOS} == "SIPROTEC" && ${OS_COUNTER[${lOS}]} -gt 100 && ${OS_COUNTER_VxWorks} -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified SIPROTEC system detected${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "NA"
    lDETECTED=1
  elif [[ ${lOS} == "SIPROTEC" && ${OS_COUNTER[${lOS}]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "SIPROTEC detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    lDETECTED=1
  fi
  if [[ ${lOS} == "CP443" && ${OS_COUNTER[${lOS}]} -gt 100 && ${OS_COUNTER_VxWorks} -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified S7-CP443 system detected${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "NA"
    lDETECTED=1
  elif [[ ${lOS} == "CP443" && ${OS_COUNTER[${lOS}]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "S7-CP443 detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    lDETECTED=1
  fi

  if [[ ${OS_COUNTER[${lOS}]} -gt 5 ]] ; then
    if [[ ${lOS} == "VxWorks\|Wind" ]]; then
      lOS_="VxWorks"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${lOS_}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    elif [[ ${lOS} == "CPU\ [34][12][0-9]-[0-9]" ]]; then
      lOS_="S7-CPU400"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${lOS_}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    elif [[ ${lDETECTED} -eq 0 ]]; then
      lOS_="${lOS}"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${lOS_}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    fi
  fi

  [[ "${OS_COUNTER[${lOS}]}" -gt 0 ]] && safe_echo "${OS_COUNTER[${lOS}]}" >> "${TMP_DIR}"/s03.tmp
}

# ====================================================================================================
# 函数: binary_architecture_detection
# 功能: 使用binwalk进行CPU架构检测
# 说明: 对RTOS固件进行架构识别，使用三种binwalk分析方法
#
# 检测方法:
#   - binwalk -Y: 可视化分析，提取有效指令序列
#   - binwalk -A: 签名分析，查找已知架构签名
#   - binwalk -%: CPU识别模块（需要cpu_rec.py）
#
# 排除项:
#   - Thumb指令: 误报率较高，已排除
#   - 高熵值(0.9xxx): 通常为加密或压缩数据
# ====================================================================================================
binary_architecture_detection() {
  # sub_module_title "Architecture detection for RTOS based systems"

  local lFILE_TO_CHECK="${1:-}"
  if ! [[ -f "${lFILE_TO_CHECK}" ]]; then
    return
  fi

  local lPRE_ARCH_=""
  print_output "[*] Architecture detection running on ""${lFILE_TO_CHECK}"

  # binwalk -Y: 可视化分析，排除Thumb指令（误报率高）
  mapfile -t PRE_ARCH_Y_ARR < <(binwalk -Y "${lFILE_TO_CHECK}" | grep "valid\ instructions" | grep -v "Thumb" | \
    awk '{print $3}' | sort -u || true)
  # binwalk -A: 签名分析，取最常见的架构
  mapfile -t PRE_ARCH_A_ARR < <(binwalk -A "${lFILE_TO_CHECK}" | grep "\ instructions," | awk '{print $3}' | \
    uniq -c | sort -n | tail -1 | awk '{print $2}' || true)

  # binwalk -%: CPU识别模块（如果可用）
  if [[ -f "${HOME}"/.config/binwalk/modules/cpu_rec.py ]]; then
    # 熵值0.9xxx通常表示加密或压缩，排除这些结果
    PRE_ARCH_CPU_REC=$(binwalk -% "${lFILE_TO_CHECK}"  | grep -v "DESCRIPTION\|None\|-----------" | grep -v "entropy=0.9" \
      | awk '{print $3}' | grep -v -e "^$" | sort | uniq -c | head -1 | awk '{print $2}' || true)
  fi

  # 将检测结果写入临时文件，格式: "检测方法;架构名称"
  for lPRE_ARCH_ in "${PRE_ARCH_Y_ARR[@]}"; do
    echo "binwalk -Y;${lPRE_ARCH_}" >> "${TMP_DIR}"/s03_arch.tmp
  done
  for lPRE_ARCH_ in "${PRE_ARCH_A_ARR[@]}"; do
    echo "binwalk -A;${lPRE_ARCH_}" >> "${TMP_DIR}"/s03_arch.tmp
  done
  if [[ -n "${PRE_ARCH_CPU_REC}" ]]; then
    echo "cpu_rec;${PRE_ARCH_CPU_REC}" >> "${TMP_DIR}"/s03_arch.tmp
  fi
}

# ====================================================================================================
# 函数: binary_architecture_reporter
# 功能: 架构检测结果报告生成
# 说明: 读取临时文件中的架构检测结果，格式化输出到日志
# ====================================================================================================
binary_architecture_reporter() {
  sub_module_title "Architecture detection for RTOS based systems"
  local lPRE_ARCH_=""
  local lSOURCE=""

  # 解析临时文件，格式: "检测方法;架构名称"
  while read -r lPRE_ARCH_; do
    lSOURCE=$(echo "${lPRE_ARCH_}" | cut -d\; -f1)
    lPRE_ARCH_=$(echo "${lPRE_ARCH_}" | cut -d\; -f2)
    print_ln
    print_output "[+] Possible architecture details found (${ORANGE}${lSOURCE}${GREEN}): ${ORANGE}${lPRE_ARCH_}${NC}"
    echo "${lPRE_ARCH_}" >> "${TMP_DIR}"/s03.tmp
  done < "${TMP_DIR}"/s03_arch.tmp
}
