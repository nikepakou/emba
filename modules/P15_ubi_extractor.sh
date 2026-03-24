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

# Description: UBI文件系统提取模块
# 依赖工具: ubireader_extract_images, ubireader_extract_files
#             - ubireader: UBI/UBIFS读取工具
#               https://github.com/jrspruitt/ubi_reader
#
# 环境变量:
#   - UBI_IMAGE: UBI文件系统检测标志
#   - FIRMWARE_PATH: 固件路径
#
# 模块定位:
#   - 当P02检测到UBI镜像时运行
#   - 原因: binwalk处理UBI有问题
#   - 使用ubireader进行专用提取

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
export PRE_THREAD_ENA=0

# P15_ubi_extractor - UBI提取主函数
# 功能: 提取UBI/UBIFS文件系统
# 参数: 无
# 条件: UBI_IMAGE=1
P15_ubi_extractor() {
  local lNEG_LOG=0

  if [[ "${UBI_IMAGE}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UBI filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    lEXTRACTION_DIR="${LOG_DIR}/firmware/ubi_extracted"
    mkdir -p "${lEXTRACTION_DIR}" || true

    ubi_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi
    lNEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

# ubi_extractor - UBI提取核心函数
# 功能: 使用ubireader提取UBI/UBIFS
# 参数:
#   $1 - lUBI_PATH: UBI文件路径
#   $2 - lEXTRACTION_DIR_: 输出目录
# 流程:
#   1. ubireader_extract_images: 提取镜像
#   2. ubireader_extract_files: 提取文件
#   3. 递归提取嵌套UBIfs镜像
ubi_extractor() {
  local lUBI_PATH="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lUBI_FILE=""
  local lUBI_INFO=""
  local lUBI_1st_ROUND_ARR=()
  local lUBI_DATA=""
  local FILES_UBI_EXT=0
  local lFILES_UBI_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lUBI_PATH}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "UBI filesystem extractor"

  print_output "[*] Extracts UBI firmware image ${ORANGE}${lUBI_PATH}${NC} with ${ORANGE}ubireader_extract_images${NC}."
  print_output "[*] File details: ${ORANGE}$(file -b "${lUBI_PATH}")${NC}"
  ubireader_extract_images -i -v -w -o "${lEXTRACTION_DIR_}"/ubi_images "${lUBI_PATH}" | tee -a "${LOG_FILE}" || true
  FILES_UBI_EXT=$(find "${lEXTRACTION_DIR_}"/ubi_images -type f | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files from the firmware image via UBI extraction round 1."

  print_output "[*] Extracts UBI firmware image ${ORANGE}${lUBI_PATH}${NC} with ${ORANGE}ubireader_extract_files${NC}."
  ubireader_extract_files -i -v -w -o "${lEXTRACTION_DIR_}"/ubi_files "${lUBI_PATH}" | tee -a "${LOG_FILE}" || true
  FILES_UBI_EXT=$(find "${lEXTRACTION_DIR_}"/ubi_files -type f | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files from the firmware image via UBI extraction round 2."

  if [[ -d "${lEXTRACTION_DIR_}" ]]; then
    mapfile -t lUBI_1st_ROUND_ARR < <(find "${lEXTRACTION_DIR_}" -type f  -print0|xargs -r -0 -P 16 -I % sh -c 'file -b "%"' | grep "UBI image" || true)

    for lUBI_DATA in "${lUBI_1st_ROUND_ARR[@]}"; do
      lUBI_FILE=$(safe_echo "${lUBI_DATA}" | cut -d: -f1)
      lUBI_INFO=$(safe_echo "${lUBI_DATA}" | cut -d: -f2)
      if [[ "${lUBI_INFO}" == *"UBIfs image"* ]]; then
        sub_module_title "UBIfs deep extraction"
        print_output "[*] Extracts UBIfs firmware image ${ORANGE}${lUBI_PATH}${NC} with ${ORANGE}ubireader_extract_files${NC}."
        print_output "[*] File details: ${ORANGE}$(file -b "${lUBI_FILE}")${NC}"
        ubireader_extract_files -l -i -w -v -o "${lEXTRACTION_DIR_}"/UBIfs_extracted "${lUBI_FILE}" | tee -a "${LOG_FILE}" || true
        FILES_UBI_EXT=$(find "${lEXTRACTION_DIR_}"/UBIfs_extracted -type f | wc -l)
        print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files from the firmware image via UBI deep extraction."
      fi
    done

    print_ln

    mapfile -t lFILES_UBI_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
    print_output "[*] Extracted ${ORANGE}${#lFILES_UBI_ARR[@]}${NC} files from the UBI firmware image."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UBI_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_UBI_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P15_ubi_extractor" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "UBI filesystem extractor" "${lUBI_PATH}" "${lEXTRACTION_DIR_}" "${#lFILES_UBI_ARR[@]}" "NA"
  else
    print_output "[-] First round UBI extractor failed!"
  fi
}
