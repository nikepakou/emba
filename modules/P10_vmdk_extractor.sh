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

# Description: VMware VMDK虚拟机磁盘提取模块
# 依赖工具: virt-filesystems, guestfish, 7z, tar
#             - virt-filesystems: 列出虚拟磁盘中的文件系统
#             - guestfish: libguestfs工具,用于访问虚拟机磁盘
#             - 7z: 备选提取工具
#             - tar: 提取归档文件
#
# 环境变量:
#   - VMDK_DETECTED: VMDK检测标志
#   - FIRMWARE_PATH: 固件路径
#   - LOG_DIR: 日志目录
#   - P99_CSV_LOG: P99模块CSV日志
#
# 模块定位:
#   - 当P02检测到VMware VMDK镜像时运行
#   - 使用virt-filesystems枚举VMDK中的文件系统
#   - 使用guestfish提取各个分区
#   - 禁用unblob(VMDK有兼容性问题)

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
export PRE_THREAD_ENA=0

# P10_vmdk_extractor - VMDK提取主函数
# 功能: 提取VMware VMDK虚拟机磁盘中的内容
# 参数: 无 (使用全局环境变量)
# 返回: 提取结果日志
#
# 提取条件: VMDK_DETECTED=1
P10_vmdk_extractor() {
  local lNEG_LOG=0

  if [[ "${VMDK_DETECTED:-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "VMDK (Virtual Machine Disk) extractor"
    pre_module_reporter "${FUNCNAME[0]}"
    EXTRACTION_DIR="${LOG_DIR}"/firmware/vmdk_extractor

    vmdk_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}"; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

# vmdk_extractor - VMDK提取核心函数
# 功能: 使用virt-filesystems和guestfish提取VMDK内容
# 参数:
#   $1 - lVMDK_PATH_: VMDK文件路径
#   $2 - lEXTRACTION_DIR_: 提取输出目录
# 返回: 提取的文件保存到目录
#
# 提取流程:
#   1. virt-filesystems枚举VMDK中的设备
#   2. 如失败,使用7z备选提取
#   3. 对每个设备使用guestfish提取
#   4. 导出为tgz格式并解压
#   5. 禁用unblob(有兼容性问题)
vmdk_extractor() {
  local lVMDK_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lMOUNT_DEV=""
  local lDEV_NAME=""
  local lRET=0
  export VMDK_FILES=0
  local lVMDK_VIRT_FS_ARR=()

  if ! [[ -f "${lVMDK_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "VMDK (Virtual Machine Disk) extractor"

  print_output "[*] Enumeration of devices in VMDK images ${ORANGE}${lVMDK_PATH_}${NC}"
  disable_strict_mode "${STRICT_MODE}" 0
  virt-filesystems -a "${lVMDK_PATH_}" > "${TMP_DIR}"/vmdk.log
  lRET="$?"

  if [[ "${lRET}" -ne 0 ]]; then
    # backup with 7z
    7z x -o"${lEXTRACTION_DIR_}" "${lVMDK_PATH_}"
    lRET="$?"
    if [[ "${lRET}" -ne 0 ]]; then
      print_output "[-] WARNING: VMDK filesystem not enumerated"
      enable_strict_mode "${STRICT_MODE}" 0
      return
    fi
  else
    mapfile -t lVMDK_VIRT_FS_ARR < "${TMP_DIR}"/vmdk.log
    for lMOUNT_DEV in "${lVMDK_VIRT_FS_ARR[@]}"; do
      print_output "[*] Found device ${ORANGE}${lMOUNT_DEV}${NC}"
    done
  fi
  enable_strict_mode "${STRICT_MODE}" 0

  for lMOUNT_DEV in "${lVMDK_VIRT_FS_ARR[@]}"; do
    lDEV_NAME=$(basename "${lMOUNT_DEV}")
    local lTMP_VMDK_MNT="${LOG_PATH_MODULE}/vmdk_mount_${lDEV_NAME}_${RANDOM}.tgz"
    print_output "[*] Mounting and extracting ${ORANGE}${lMOUNT_DEV}${NC} to ${ORANGE}${lTMP_VMDK_MNT}${NC} file"
    # if troubles ahead with vmdk mount, remove the error redirection
    # guestmount -a "${lVMDK_PATH_}" -m "${lMOUNT_DEV}" --ro "${lTMP_VMDK_MNT}" 2>/dev/null || { print_error "[-] Mounting VMDK ${lVMDK_PATH_} failed ..."; continue; }
    guestfish --ro -a "${lVMDK_PATH_}" -m "${lMOUNT_DEV}" tgz-out / "${lTMP_VMDK_MNT}" || { print_error "[-] Extracting VMDK ${lVMDK_PATH_} failed ..."; continue; }
    if [[ -f "${lTMP_VMDK_MNT}" ]]; then
      print_output "[*] Extracting ${ORANGE}${lMOUNT_DEV}${NC} to firmware directory ${ORANGE}${lEXTRACTION_DIR_}/${lDEV_NAME}${NC}"
      mkdir -p "${lEXTRACTION_DIR_}/${lDEV_NAME}" || true
      tar -xvf "${lTMP_VMDK_MNT}" -C "${lEXTRACTION_DIR_}/${lDEV_NAME}" || { print_error "[-] Extracting VMDK ${lTMP_VMDK_MNT} to ${lEXTRACTION_DIR_}/${lDEV_NAME} failed ..."; continue; }
      rm "${lTMP_VMDK_MNT}" || true
    fi
  done

  if [[ -d "${lEXTRACTION_DIR_}" ]]; then
    local lVMDK_FILES_ARR=()
    local lBINARY=""
    local lWAIT_PIDS_P99_ARR=()
    mapfile -t lVMDK_FILES_ARR < <(find "${lEXTRACTION_DIR_}" -type f)

    print_output "[*] Extracted ${ORANGE}${#lVMDK_FILES_ARR[@]}${NC} files from the firmware image."
    print_output "[*] Populating backend data for ${ORANGE}${#lVMDK_FILES_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lVMDK_FILES_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P10_vmdk_extractor" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "VMDK extractor" "${lVMDK_PATH_}" "${lEXTRACTION_DIR_}" "${#lVMDK_FILES_ARR[@]}" "NA"
    # currently unblob has issues with VMDKs. We need to disable it for this extraction process
    safe_echo 0 > "${TMP_DIR}"/unblob_disable.cfg
  fi
}
