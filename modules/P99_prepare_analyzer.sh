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

# Description: 分析准备工作模块 - 为后续分析做初始化准备
# 依赖工具: 无 (纯逻辑处理)
#
# 环境变量:
#   - THREADED: 多线程模式标志
#   - WAIT_PIDS: 等待的进程PID数组
#   - LINUX_PATH_COUNTER: Linux路径计数器
#   - ROOT_PATH: 检测到的根路径数组
#   - FIRMWARE: 固件标志 (1=成功提取固件)
#   - FIRMWARE_PATH: 固件路径
#   - P99_CSV_LOG: P99模块CSV日志
#   - RTOS: 实时操作系统标志
#   - UEFI_VERIFIED: UEFI验证标志
#   - UEFI_DETECTED: UEFI检测标志
#   - WINDOWS_EXE: Windows可执行文件标志
#   - KERNEL: Linux内核标志
#   - SBOM_MINIMAL: SBOM最小化模式
#
# 模块定位:
#   - P阶段最后一个模块(Preparation phase)
#   - 在所有其他P模块完成后执行
#   - 负责分析前的最终准备工作
#
# 准备工作内容:
#   1. 等待所有P模块完成
#   2. 统计Linux路径数量
#   3. 确认FIRMWARE_PATH设置
#   4. check_firmware: 快速检查固件
#   5. 初始化P99_CSV_LOG(如果不存在)
#   6. prepare_all_file_arrays: 准备文件数组
#   7. architecture_check: 检查架构
#   8. architecture_dep_check: 检查架构依赖
#   9. detect_root_dir_helper: 辅助检测根目录
#   10. set_etc_paths: 设置etc路径
#   11. 输出检测结果摘要

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
export PRE_THREAD_ENA=0

# P99_prepare_analyzer - 分析准备主函数
# 功能: 执行分析前的所有准备工作
# 参数: 无 (使用全局环境变量)
# 返回: 完成准备工作,设置分析所需的环境变量
#
# 详细流程:
#   1. 等待所有P模块线程完成
#   2. 使用linux_basic_identification统计Linux路径
#   3. 如果有Linux路径或多个根路径,设置FIRMWARE=1和FIRMWARE_PATH
#   4. 调用check_firmware进行快速固件检查
#   5. 如果P99_CSV_LOG不存在,初始化文件列表
#   6. 调用prepare_all_file_arrays准备文件数组
#   7. 如果未检测到内核,执行架构检查和依赖检查
#   8. 如果未验证UEFI且无根路径,调用detect_root_dir_helper
#   9. 调用set_etc_paths设置etc路径
#   10. 根据检测结果输出摘要信息(UEFI/RTOS/Android/Windows等)
#   11. 记录统计信息到日志
P99_prepare_analyzer() {

  # this module is the latest in the preparation phase. So, wait for all the others
  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS[@]}"

  module_log_init "${FUNCNAME[0]}"
  module_title "Analysis preparation"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=1

  export LINUX_PATH_COUNTER=0
  LINUX_PATH_COUNTER="$(linux_basic_identification "${LOG_DIR}/firmware")"

  # we have a linux:
  if [[ ${LINUX_PATH_COUNTER} -gt 0 || ${#ROOT_PATH[@]} -gt 1 ]] ; then
    export FIRMWARE=1
    # FIRMWARE_PATH="$(abs_path "${OUTPUT_DIR}")"
    export FIRMWARE_PATH="${LOG_DIR}"/firmware
    backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
  fi

  print_output "[*] Quick check for Linux operating-system"
  check_firmware

  # The following code is just in case we have not already created our P99_CSV_LOG file
  local lFILES_ARR=()
  local lBINARY=""
  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] INFO: No ${P99_CSV_LOG} log file available ... trying to create it now"
    mapfile -t lFILES_ARR < <(find "${LOG_DIR}/firmware" -type f)
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"
  fi

  # do we need this. We should check it and remove the complete code
  # as we rely on P99_CSV_LOG
  prepare_all_file_arrays "${FIRMWARE_PATH}"

  if [[ ${KERNEL} -eq 0 ]] ; then
    architecture_check "${FIRMWARE_PATH}"
    architecture_dep_check
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  if [[ "${UEFI_VERIFIED}" -ne 1 ]] && [[ "${#ROOT_PATH[@]}" -eq 0 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}" "main"
  fi

  set_etc_paths
  print_ln
  if [[ "${RTOS}" -eq 1 ]] && [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
    print_output "[+] UEFI firmware detected"
    if [[ -f "${LOG_DIR}"/p35_uefi_extractor.txt ]]; then
      write_link "p35"
    fi
  elif [[ "${RTOS}" -eq 1 ]] && [[ "${UEFI_DETECTED}" -eq 1 ]]; then
    print_output "[*] Possible UEFI firmware detected"
    if [[ -f "${LOG_DIR}"/p02_firmware_bin_file_check.txt ]]; then
      write_link "p02"
    fi
  elif [[ "${WINDOWS_EXE}" -eq 1 ]]; then
    print_output "[*] Windows binaries detected"
    if [[ -f "${LOG_DIR}"/p07_windows_exe_extract.txt ]]; then
      write_link "p07"
    fi
  elif grep -q "Identified Android APK package - performing APK checks" "${P02_LOG}"; then
    print_output "[+] Android APK package detected"
    write_link "p02"
  elif [[ "${RTOS}" -eq 1 ]]; then
    print_output "[*] Possible RTOS system detected"
  fi

  write_log "[*] Statistics:${ARCH:-NA}:${D_END:-NA}"
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

