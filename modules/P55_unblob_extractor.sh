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

# Description: 使用unblob提取固件到模块日志目录
# 依赖工具: unblob, tree
#             - unblob: 通用固件提取工具,支持多种格式
#               官方网站: https://github.com/onekey-sec/unblob
#               支持格式: zip, tar, ar, cab, cpio, iso9660, gzip, bzip2, xz, lzma, zstd等
#             - tree: 树状显示目录结构
#
# 环境变量:
#   - UEFI_VERIFIED: UEFI固件验证标志
#   - RTOS: 实时操作系统标志 (1=未找到Linux, 0=已找到Linux)
#   - UNBLOB: unblob启用标志 (0=禁用, 1=启用)
#   - DISABLE_DEEP: 禁用深度提取标志
#   - SBOM_MINIMAL: SBOM最小化模式
#   - FULL_EMULATION: 完整系统仿真标志
#   - DIFF_MODE: 差异比较模式
#   - FIRMWARE_PATH_BAK: 原始固件路径备份
#
# 模块定位:
#   - 主要固件提取工具
#   - 当前结果主要用于评估目的(不直接用于后续分析)
#   - 当UEFI_VERIFIED=1时跳过
#
# 双模式提取:
#   1. 主模式: 使用unblob提取固件
#   2. 恢复模式(FULL_EMULATION=1): 如果unblob未能提取到Linux文件系统,
#      尝试使用binwalk作为恢复方案
#
# 重要说明:
#   - unblob是当前EMBA的主要固件提取工具
#   - binwalk已被标记为有已知问题(符号链接丢失等)
#   - 未来可能会移除binwalk作为主要提取方式

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
# 此模块用于提取固件,会阻塞需要在其后执行的模块
export PRE_THREAD_ENA=0

# P55_unblob_extractor - Unblob固件提取主函数
# 功能: 使用unblob提取固件中的嵌套文件
# 参数: 无 (使用全局环境变量)
# 返回: 提取结果日志
#
# 提取条件 (跳过场景):
#   - UEFI_VERIFIED=1: 已验证的UEFI固件
#   - RTOS=0: 已找到Linux文件系统
#   - UNBLOB=0: unblob被禁用
#   - DISABLE_DEEP=1: 深度提取被禁用
#   - 输入为目录而非文件
#
# 提取流程:
#   1. 检查是否需要跳过
#   2. 检查unblob是否安装
#   3. 使用unblobber函数进行提取
#   4. 清理不可打印字符的路径
#   5. 对提取的文件进行架构分析
#   6. 统计Linux路径数量
#   7. 如果是完整仿真模式且未找到Linux,使用binwalk恢复
P55_unblob_extractor() {
  module_log_init "${FUNCNAME[0]}"

  if [[ "${UEFI_VERIFIED}" -eq 1 || "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # shellcheck disable=SC2153
  if [[ -d "${FIRMWARE_PATH}" ]] && [[ "${RTOS}" -eq 1 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}"
  fi

  # If we have found a linux filesystem we do not need an unblob extraction
  if [[ ${RTOS} -eq 0 ]] ; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  if [[ -f "${TMP_DIR}""/unblob_disable.cfg" ]]; then
    # if we disable unblob from a background module we need to work with a file to
    # store the state of this variable (bash rules ;))
    UNBLOB="$(cat "${TMP_DIR}"/unblob_disable.cfg)"
  fi

  if [[ "${UNBLOB:-1}" -eq 0 ]]; then
    if [[ -f "${TMP_DIR}""/unblob_disable.cfg" ]]; then
      print_output "[-] Unblob module automatically disabled from other module."
    else
      print_output "[-] Unblob module currently disabled - enable it in emba setting the UNBLOB variable to 1"
    fi
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lFW_PATH_UNBLOB="${FIRMWARE_PATH_BAK}"

  if [[ -d "${lFW_PATH_UNBLOB}" ]]; then
    print_output "[-] Unblob module only deals with firmware files - directories are handled via deep extractor"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  if ! command -v unblob >/dev/null; then
    print_output "[-] Unblob not correct installed - check your installation"
    return
  fi

  local lFILES_UNBLOB_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  module_title "Unblob binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  local lLINUX_PATH_COUNTER_UNBLOB=0
  local lOUTPUT_DIR_UNBLOB="${LOG_DIR}"/firmware/unblob_extracted

  if [[ -f "${lFW_PATH_UNBLOB}" ]]; then
    unblobber "${lFW_PATH_UNBLOB}" "${lOUTPUT_DIR_UNBLOB}" 0
  fi

  if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    print_ln
    if [[ -d "${lOUTPUT_DIR_UNBLOB}" ]]; then
      remove_uprintable_paths "${lOUTPUT_DIR_UNBLOB}"
      mapfile -t lFILES_UNBLOB_ARR < <(find "${lOUTPUT_DIR_UNBLOB}" -type f ! -name "*.raw")
    fi

    if [[ "${#lFILES_UNBLOB_ARR[@]}" -gt 0 ]]; then
      print_output "[*] Extracted ${ORANGE}${#lFILES_UNBLOB_ARR[@]}${NC} files."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UNBLOB_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_UNBLOB_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done

      lLINUX_PATH_COUNTER_UNBLOB=$(linux_basic_identification "${lOUTPUT_DIR_UNBLOB}" "${FUNCNAME[0]}")
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      sub_module_title "Firmware extraction details"
      print_output "[*] ${ORANGE}Unblob${NC} results:"
      print_output "[*] Found ${ORANGE}${#lFILES_UNBLOB_ARR[@]}${NC} files."
      print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_UNBLOB}${NC}."
      print_ln
      tree -sh "${lOUTPUT_DIR_UNBLOB}" | tee -a "${LOG_FILE}"
      print_ln
    fi
  fi

  detect_root_dir_helper "${lOUTPUT_DIR_UNBLOB}"

  # this is the 2nd run for full sytem emulation
  # further comments on this mechanism in P50
  # this will be removed in the future after binwalk is running as expected
  if [[ "${FULL_EMULATION}" -eq 1 && "${RTOS}" -eq 1 ]]; then
    local lOUTPUT_DIR_BINWALK=""
    local lFILES_BINWALK_ARR=()

    lOUTPUT_DIR_BINWALK="${lOUTPUT_DIR_UNBLOB//unblob/binwalk_recover}"
    binwalker_matryoshka "${lFW_PATH_UNBLOB}" "${lOUTPUT_DIR_BINWALK}"
    if [[ -d "${lOUTPUT_DIR_BINWALK}" ]]; then
      remove_uprintable_paths "${lOUTPUT_DIR_BINWALK}"
      mapfile -t lFILES_BINWALK_ARR < <(find "${lOUTPUT_DIR_BINWALK}" -type f ! -name "*.raw")
    fi

    if [[ "${#lFILES_BINWALK_ARR[@]}" -gt 0 ]]; then
      print_output "[*] Extracted ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_BINWALK_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done

      lLINUX_PATH_COUNTER_BINWALK=$(linux_basic_identification "${lOUTPUT_DIR_BINWALK}" "${FUNCNAME[0]}")
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      sub_module_title "Firmware extraction details"
      print_output "[*] ${ORANGE}Binwalk recovery${NC} results:"
      print_output "[*] Found ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files."
      print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_BINWALK}${NC}."
      print_ln
      tree -sh "${lOUTPUT_DIR_BINWALK}" | tee -a "${LOG_FILE}"
      detect_root_dir_helper "${lOUTPUT_DIR_BINWALK}"
      write_csv_log "FILES Binwalk recovery mode" "LINUX_PATH_COUNTER Binwalk"
      write_csv_log "${#lFILES_BINWALK_ARR[@]}" "${lLINUX_PATH_COUNTER_BINWALK}"
    fi
  fi

  write_csv_log "FILES Unblob" "LINUX_PATH_COUNTER Unblob"
  write_csv_log "${#lFILES_UNBLOB_ARR[@]}" "${lLINUX_PATH_COUNTER_UNBLOB}"

  module_end_log "${FUNCNAME[0]}" "${#lFILES_UNBLOB_ARR[@]}"
}

# unblobber - Unblob固件提取核心函数
# 功能: 调用unblob工具提取固件中的文件
# 参数:
#   $1 - lFIRMWARE_PATH: 要提取的固件文件路径
#   $2 - lOUTPUT_DIR_UNBLOB: 输出目录路径
#   $3 - lVERBOSE: 详细输出标志 (0=普通, 1=详细)
# 返回: 提取的文件到指定目录
#
# unblob命令参数:
#   - -v: 详细输出模式
#   - -k: 保留已存在的文件(不覆盖)
#   - --log: 日志文件路径
#   - -e: 提取目录
#
# 超时设置:
#   - 默认超时: 300分钟
#   - 使用timeout命令确保提取不会无限等待
#   - --preserve-status: 保留命令退出状态
#   - --signal SIGINT: 允许优雅中断
#
# 日志处理:
#   - 使用safe_logging处理输出
#   - 避免日志注入攻击
unblobber() {
  local lFIRMWARE_PATH="${1:-}"
  local lOUTPUT_DIR_UNBLOB="${2:-}"
  local lVERBOSE="${3:-0}"
  local lUNBLOB_BIN="unblob"
  local lTIMEOUT="300m"
  local lUNBLOB_LOG=""
  lUNBLOB_LOG="${LOG_PATH_MODULE}/unblob_$(basename "${lFIRMWARE_PATH}")_${RANDOM}.log"

  if [[ "${DIFF_MODE}" -ne 1 ]]; then
    sub_module_title "Analyze binary firmware $(basename "${lFIRMWARE_PATH}") with unblob"
  fi

  print_output "[*] Extracting binary blob ${ORANGE}$(basename "${lFIRMWARE_PATH}")${NC} to directory ${ORANGE}${lOUTPUT_DIR_UNBLOB}${NC}"

  if ! [[ -d "${lOUTPUT_DIR_UNBLOB}" ]]; then
    mkdir -p "${lOUTPUT_DIR_UNBLOB}"
  fi

  if [[ "${lVERBOSE}" -eq 1 ]]; then
    # Warning: the safe_logging is very slow.
    # TODO: We need to check on this!
    timeout --preserve-status --signal SIGINT "${lTIMEOUT}" "${lUNBLOB_BIN}" -v -k --log "${lUNBLOB_LOG}" -e "${lOUTPUT_DIR_UNBLOB}" "${lFIRMWARE_PATH}" \
      |& safe_logging "${LOG_FILE}" 0 || true
  else
    local COLUMNS=""
    COLUMNS=100 timeout --preserve-status --signal SIGINT "${lTIMEOUT}" "${lUNBLOB_BIN}" -k --log "${lUNBLOB_LOG}" -e "${lOUTPUT_DIR_UNBLOB}" "${lFIRMWARE_PATH}" \
      |& safe_logging "${LOG_FILE}" 0 || true
  fi
}

