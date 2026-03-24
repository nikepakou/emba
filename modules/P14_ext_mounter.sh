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

# Description: EXT文件系统挂载提取模块
# 依赖工具: mount, umount, cp
#             - mount: 挂载EXT2/3/4文件系统
#             - umount: 卸载文件系统
#             - cp: 复制文件
#
# 环境变量:
#   - EXT_IMAGE: EXT文件系统检测标志
#   - FIRMWARE_PATH: 固件路径
#
# 模块定位:
#   - 当P02检测到EXT文件系统镜像时运行
#   - 原因: binwalk会破坏权限和符号链接
#   - 直接挂载可保留文件权限和链接

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
export PRE_THREAD_ENA=0

# P14_ext_mounter - EXT文件系统提取主函数
# 功能: 挂载并提取EXT2/3/4文件系统
# 参数: 无
# 提取条件: EXT_IMAGE=1
P14_ext_mounter() {
  local lNEG_LOG=0
  if [[ "${EXT_IMAGE:-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "EXT filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    print_output "[*] Connect to device ${ORANGE}${FIRMWARE_PATH}${NC}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/ext_mount_filesystem/

    ext_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

# ext_extractor - EXT提取核心函数
# 功能: 挂载EXT文件系统并提取文件
# 参数:
#   $1 - lEXT_PATH_: EXT文件系统文件路径
#   $2 - lEXTRACTION_DIR_: 提取输出目录
# 流程: 挂载->复制->卸载->清理
ext_extractor() {
  local lEXT_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lTMP_EXT_MOUNT=""
  lTMP_EXT_MOUNT="$(mktemp -d "${TMP_DIR}/ext_mount_XXXXXX")"
  local lFILES_EXT_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lEXT_PATH_}" ]]; then
    print_output "[-] No EXT filesystem for extraction provided"
    return
  fi

  sub_module_title "EXT filesystem extractor"

  print_output "[*] Trying to mount ${ORANGE}${lEXT_PATH_}${NC} to ${ORANGE}${lTMP_EXT_MOUNT}${NC} directory"
  mount -o ro "${lEXT_PATH_}" "${lTMP_EXT_MOUNT}" || { print_output "[-] EXT filesystem mount failed"; return; }
  if mount | grep -q ext_mount; then
    if [[ -n "$(find "${lTMP_EXT_MOUNT}" -mindepth 1 -print -quit)" ]]; then
      print_output "[*] No mounted files found in ${ORANGE}${lTMP_EXT_MOUNT}${NC} -> return now"
      return
    fi

    print_output "[*] Copying ${ORANGE}${lTMP_EXT_MOUNT}${NC} to firmware tmp directory (${lEXTRACTION_DIR_})"
    mkdir -p "${lEXTRACTION_DIR_}"
    cp -pri "${lTMP_EXT_MOUNT}"/* "${lEXTRACTION_DIR_}"
    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
    find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln
    print_output "[*] Unmounting ${ORANGE}${lTMP_EXT_MOUNT}${NC} directory"

    mapfile -t lFILES_EXT_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
    print_output "[*] Extracted ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files from the EXT filesystem."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_EXT_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P14_ext_mounter" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "EXT filesystem extractor" "${lEXT_PATH_}" "${lEXTRACTION_DIR_}" "${#lFILES_EXT_ARR[@]}" "NA"
  fi
  umount "${lTMP_EXT_MOUNT}" || true
  [[ -d "${lTMP_EXT_MOUNT}" ]] && rm -rf "${lTMP_EXT_MOUNT}"
}
