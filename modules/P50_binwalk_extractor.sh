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

# Description: 使用binwalk提取固件(备选模块)
# 依赖工具: binwalk, tree, iconv
#             - binwalk: 固件分析工具,用于识别和提取固件中的嵌套文件
#             - tree: 树状显示目录结构
#             - iconv: 字符编码转换,用于处理不可打印字符
#
# 环境变量:
#   - UEFI_VERIFIED: UEFI固件验证标志
#   - RTOS: 实时操作系统标志 (1=未找到Linux, 0=已找到Linux)
#   - DJI_DETECTED: DJI固件检测标志
#   - WINDOWS_EXE: Windows可执行文件标志
#   - FULL_EMULATION: 完整系统仿真标志
#   - FIRMWARE_PATH_BAK: 原始固件路径备份
#
# 模块定位:
#   - 这是一个备选(Fallback)模块
#   - 主要用于unblob提取失败的特殊情况
#   - 例如: https://github.com/onekey-sec/sasquatch/issues/19
#
# 使用限制:
#   - Binwalk v3在处理符号链接时有问题
#   - 当启用完整系统仿真(FULL_EMULATION=1)时,自动禁用binwalk
#   - 仅处理文件,不处理目录(目录由deep extractor处理)
#
# 已知问题:
#   - 路径中的不可打印字符可能导致问题
#   - 符号链接可能在提取过程中丢失
#   - 可执行文件权限可能丢失

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
# 此模块用于提取固件,会阻塞需要在其后执行的模块
export PRE_THREAD_ENA=0

# P50_binwalk_extractor - Binwalk固件提取主函数
# 功能: 使用binwalk提取固件中的嵌套文件
# 参数: 无 (使用全局环境变量)
# 返回: 提取结果日志
#
# 提取条件 (跳过场景):
#   - UEFI_VERIFIED=1: 已验证的UEFI固件
#   - RTOS=0: 已找到Linux文件系统
#   - DJI_DETECTED=1: 已检测DJI固件
#   - WINDOWS_EXE=1: Windows可执行文件
#   - FULL_EMULATION=1: 完整系统仿真模式(binwalk有已知bug)
#
# 提取流程:
#   1. 检查是否需要跳过(已由其他提取器处理)
#   2. 使用binwalker_matryoshka进行递归提取
#   3. 清理不可打印字符的路径
#   4. 对提取的文件进行架构分析
#   5. 使用linux_basic_identification统计Linux路径
#   6. 输出目录树结构到日志
P50_binwalk_extractor() {
  module_log_init "${FUNCNAME[0]}"

  # shellcheck disable=SC2153
  if [[ -d "${FIRMWARE_PATH}" ]] && [[ "${RTOS}" -eq 1 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}"
  fi

  # if we have a verified UEFI firmware we do not need to do anything here
  # if we have already found a linux (RTOS==0) we do not need to do anything here
  if [[ "${UEFI_VERIFIED}" -eq 1 ]] || [[ "${RTOS}" -eq 0 ]] || [[ "${DJI_DETECTED}" -eq 1 ]] || [[ "${WINDOWS_EXE}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # We have seen multiple issues in system emulation while using binwalk
  # * unprintable chars in paths -> remediation in place
  # * lost symlinks in different firmware extractions -> Todo: Issue
  # * lost permissions of executables -> remediation in place
  # Currently we disable binwalk here and switch automatically to unblob is main extractor while
  # system emulation runs. If unblob fails we are going to try an additional extraction round with
  # binwalk.
  if [[ "${FULL_EMULATION}" -eq 1 ]]; then
    print_output "[-] Binwalk v3 has issues with symbolic links and is disabled for system emulation"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # we do not rely on any EMBA extraction mechanism -> we use the original firmware file
  local lFW_PATH_BINWALK="${FIRMWARE_PATH_BAK}"

  if [[ -d "${lFW_PATH_BINWALK}" ]]; then
    print_output "[-] Binwalk module only deals with firmware files - directories should be already handled via deep extractor"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lFILES_BINWALK_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  module_title "Binwalk binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  local lLINUX_PATH_COUNTER_BINWALK=0
  local lOUTPUT_DIR_BINWALK="${LOG_DIR}"/firmware/binwalk_extracted

  if [[ -f "${lFW_PATH_BINWALK}" ]]; then
    binwalker_matryoshka "${lFW_PATH_BINWALK}" "${lOUTPUT_DIR_BINWALK}"
  fi

  print_ln
  if [[ -d "${lOUTPUT_DIR_BINWALK}" ]]; then
    remove_uprintable_paths "${lOUTPUT_DIR_BINWALK}"
    mapfile -t lFILES_BINWALK_ARR < <(find "${lOUTPUT_DIR_BINWALK}" -type f)
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
    print_output "[*] ${ORANGE}Binwalk${NC} results:"
    print_output "[*] Found ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files."
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_BINWALK}${NC}."
    print_ln
    tree -sh "${lOUTPUT_DIR_BINWALK}" | tee -a "${LOG_FILE}"
  fi

  detect_root_dir_helper "${lOUTPUT_DIR_BINWALK}"

  write_csv_log "FILES Binwalk" "LINUX_PATH_COUNTER Binwalk"
  write_csv_log "${#lFILES_BINWALK_ARR[@]}" "${lLINUX_PATH_COUNTER_BINWALK}"

  module_end_log "${FUNCNAME[0]}" "${#lFILES_BINWALK_ARR[@]}"
}

# linux_basic_identification - Linux基本路径识别函数
# 功能: 统计提取结果中包含Linux典型路径的文件数量
# 参数:
#   $1 - lFIRMWARE_PATH_CHECK: 要检查的固件目录路径
#   $2 - lIDENTIFIER: 模块标识符(可选)
# 返回: Linux路径计数器(匹配的文件数量)
#
# 匹配的关键路径:
#   - /bin/: 二进制文件目录
#   - /busybox: BusyBox可执行文件
#   - /shadow: 密码影子文件
#   - /passwd: 用户账户文件
#   - /sbin/: 系统二进制目录
#   - /etc/: 系统配置文件目录
#
# 用途: 用于判断是否成功提取到Linux文件系统
linux_basic_identification() {
  local lFIRMWARE_PATH_CHECK="${1:-}"
  local lIDENTIFIER="${2:-}"
  local lLINUX_PATH_COUNTER_BINWALK=0

  if ! [[ -d "${lFIRMWARE_PATH_CHECK}" ]]; then
    return
  fi
  if [[ -f "${P99_CSV_LOG}" ]]; then
    if [[ -n "${lIDENTIFIER}" ]]; then
      lLINUX_PATH_COUNTER_BINWALK="$(grep "${lIDENTIFIER}" "${P99_CSV_LOG}" | grep -c "/bin/\|/busybox;\|/shadow;\|/passwd;\|/sbin/\|/etc/" || true)"
    else
      lLINUX_PATH_COUNTER_BINWALK="$(grep -c "/bin/\|/busybox;\|/shadow;\|/passwd;\|/sbin/\|/etc/" "${P99_CSV_LOG}" || true)"
    fi
  fi
  echo "${lLINUX_PATH_COUNTER_BINWALK}"
}

# remove_uprintable_paths - 不可打印字符路径清理函数
# 功能: 清理文件名中的不可打印字符,避免后续处理问题
# 参数:
#   $1 - lOUTPUT_DIR_BINWALK: 要清理的目录路径
# 返回: 修改文件名,将不可打印字符替换为可打印字符
#
# 处理逻辑:
#   1. 查找所有包含不可打印字符的文件名
#   2. 使用iconv将UTF-8转换为ASCII ( translit模式)
#   3. 重命名文件为清理后的名称
#
# 原因: binwalk提取的固件可能包含非标准字符,
#       这些字符会导致后续处理(如系统仿真)出现问题
remove_uprintable_paths() {
  local lOUTPUT_DIR_BINWALK="${1:-}"

  local lFIRMWARE_UNPRINT_FILES_ARR=()
  local lFW_FILE=""
  local lNEW_FILE=""

  mapfile -t lFIRMWARE_UNPRINT_FILES_ARR < <(find "${lOUTPUT_DIR_BINWALK}" -name '*[^[:print:]]*')
  if [[ "${#lFIRMWARE_UNPRINT_FILES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Unprintable characters detected in extracted files -> cleanup started"
    for lFW_FILE in "${lFIRMWARE_UNPRINT_FILES_ARR[@]}"; do
      print_output "[*] Cleanup of ${lFW_FILE} with unprintable characters"
      # print_output "[*] Moving ${lFW_FILE} to ${lFW_FILE//[![:print:]]/_}"
      # mv "${lFW_FILE}" "${lFW_FILE//[![:print:]]/_}" || true
      lNEW_FILE=$(iconv -f UTF-8 -t ASCII//TRANSLIT <<<"${lFW_FILE}")
      print_output "[*] Moving ${lFW_FILE} to ${lNEW_FILE}"
      mv "${lFW_FILE}" "${lNEW_FILE}" || print_output "[-] Cleanup of file ${lFW_FILE} not possible"
    done
  fi
}
