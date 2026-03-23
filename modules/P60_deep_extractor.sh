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

# Description: 深度固件提取器 - 递归提取固件中的嵌套文件
# 依赖工具: unblob, binwalk, md5sum, tree, du
#             - unblob: 通用固件提取工具(默认)
#             - binwalk: 备选固件提取工具
#             - md5sum: 计算文件MD5用于去重
#             - tree: 树状显示目录结构
#             - du: 磁盘空间检查
#
# 环境变量:
#   - RTOS: 实时操作系统标志 (1=未找到Linux, 0=已找到Linux)
#   - UEFI_VERIFIED: UEFI固件验证标志
#   - DJI_DETECTED: DJI固件检测标志
#   - DISABLE_DEEP: 禁用深度提取标志
#   - DEEP_EXT_DEPTH: 深度提取轮数 (默认4轮)
#   - MAX_EXT_SPACE: 最大允许磁盘空间
#   - DISK_SPACE_CRIT: 磁盘空间危急标志
#   - FIRMWARE_PATH_CP: 固件副本路径
#   - P99_CSV_LOG: P99模块CSV日志
#
# 模块定位:
#   - 深度提取模块,对P55/P50提取后的文件进行二次/多次提取
#   - 递归处理: 每轮提取后检查是否发现新文件,继续提取
#   - 多轮迭代: 默认4轮深度提取,每轮使用不同的提取策略
#
# 深度提取流程:
#   1. 检查磁盘空间是否充足
#   2. 迭代提取(最多4轮):
#      - 第1-3轮: 使用EMBA特定提取器处理特定格式
#      - 第4轮: 使用unblob进行最终提取
#   3. 每轮提取后检测是否发现Linux文件系统
#   4. 发现Linux文件系统后停止提取

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
# 此模块用于提取固件,会阻塞需要在其后执行的模块
export PRE_THREAD_ENA=0

# P60_deep_extractor - 深度固件提取主函数
# 功能: 协调多轮深度提取流程
# 参数: 无 (使用全局环境变量)
# 返回: 提取结果日志
#
# 提取条件 (跳过场景):
#   - RTOS=0: 已找到Linux文件系统
#   - UEFI_VERIFIED=1: 已验证的UEFI固件
#   - DJI_DETECTED=1: 已检测DJI固件
#   - DISABLE_DEEP=1: 深度提取被禁用
#
# 提取流程:
#   1. 检查磁盘空间
#   2. 如果磁盘空间充足,执行deep_extractor
#   3. 统计提取后的文件数量
#   4. 对新增文件进行架构分析
#   5. 统计Linux路径数量
#   6. 输出目录树结构
#   7. 如果发现root路径,记录到CSV
P60_deep_extractor() {
  module_log_init "${FUNCNAME[0]}"

  export DISK_SPACE_CRIT=0
  local lR_PATH=""
  # dirty solution to know if have not run the extractor and we just re-created the P99 log
  export NO_EXTRACTED=0

  # If we have not found a linux filesystem we try to do an extraction round on every file multiple times
  # If we already know it is a linux (RTOS -> 0) or it is UEFI (UEFI_VERIFIED -> 1) we do not need to run
  # the deep extractor
  if [[ "${RTOS:-1}" -eq 0 ]] || [[ "${UEFI_VERIFIED:-0}" -eq 1 ]] || [[ "${DJI_DETECTED:-0}" -eq 1 ]] || [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Binary firmware deep extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  local lFILES_P99_BEFORE=0
  if [[ -f "${P99_CSV_LOG}" ]]; then
    lFILES_P99_BEFORE=$(wc -l "${P99_CSV_LOG}")
    lFILES_P99_BEFORE="${lFILES_P99_BEFORE/\ *}"
  fi

  check_disk_space
  if ! [[ "${DISK_SPACE}" -gt "${MAX_EXT_SPACE}" ]]; then
    deep_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no deep extraction performed" "main"
    DISK_SPACE_CRIT=1
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 1
    return
  fi

  mapfile -t lFILES_EXT_ARR < <(find "${FIRMWARE_PATH_CP}" -type f ! -name "*.raw")
  local lFILES_P99=0
  if [[ -f "${P99_CSV_LOG}" ]]; then
    lFILES_P99=$(wc -l "${P99_CSV_LOG}")
    lFILES_P99="${lFILES_P99/\ *}"
  fi

  # we only do the P99 populating if we have done something with the deep extractor
  # and we have now more files found as already known in P99
  if [[ "${NO_EXTRACTED}" -eq 0 ]] && [[ "${#lFILES_EXT_ARR[@]}" -gt "${lFILES_P99}" ]]; then
    sub_module_title "Extraction results"

    print_output "[*] Extracted ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files."

    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_EXT_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done

    local lLINUX_PATH_COUNTER=0
    lLINUX_PATH_COUNTER=$(linux_basic_identification "${FIRMWARE_PATH_CP}")
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    print_ln
    print_output "[*] Found ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files at all."
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER}${NC}."
    print_output "[*] Before deep extraction we had ${ORANGE}${lFILES_P99_BEFORE}${NC} files, after deep extraction we have now ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files extracted."

    tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="${FIRMWARE_PATH_CP}"

    if [[ "${#ROOT_PATH[@]}" -gt 0 ]] ; then
      write_csv_log "FILES" "LINUX_PATH_COUNTER" "Root PATH detected"
      for lR_PATH in "${ROOT_PATH[@]}"; do
        write_csv_log "${#lFILES_EXT_ARR[@]}" "${lLINUX_PATH_COUNTER}" "${lR_PATH}"
      done
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${#lFILES_EXT_ARR[@]}"
}

# check_disk_space - 磁盘空间检查函数
# 功能: 检查固件目录占用的磁盘空间
# 参数: 无 (使用全局环境变量FIRMWARE_PATH_CP)
# 返回: 设置全局变量DISK_SPACE (单位: MB)
#
# 检查逻辑:
#   - 使用du命令计算固件目录大小
#   - --max-depth=1: 只计算顶层目录
#   - --exclude="proc": 排除/proc虚拟文件系统
#   - 输出排序后取最大值
check_disk_space() {
  export DISK_SPACE=0
  DISK_SPACE=$(du -hm "${FIRMWARE_PATH_CP}" --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1 || true)
}

# deep_extractor - 深度提取执行函数
# 功能: 执行多轮深度提取
# 参数: 无
# 返回: 迭代提取文件到固件目录
#
# 深度提取策略:
#   - 默认4轮提取 (由DEEP_EXT_DEPTH控制)
#   - 每轮提取后使用detect_root_dir_helper检测Linux文件系统
#   - 发现Linux文件系统后立即停止
#   - 磁盘空间不足时停止
#
# 提取轮次:
#   - 1st round: 初始提取
#   - 2nd round: 二次提取
#   - 3rd round: 三次提取
#   - 4th round: 最终unblob提取 (带有警告信息)
#
# 特殊情况:
#   - 如果P99_CSV_LOG不存在,先初始化文件列表
#   - 如果初始已找到Linux文件系统,设置NO_EXTRACTED=1
deep_extractor() {
  sub_module_title "Deep extraction mode"

  local lFILES_DEEP_PRE_ARR=()
  local lBINARY=""
  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] No ${P99_CSV_LOG} log file available ... trying to create it now"
    mapfile -t lFILES_DEEP_PRE_ARR < <(find "${LOG_DIR}/firmware" -type f)
    if [[ -f "${FIRMWARE_PATH}" ]]; then
      lFILES_DEEP_PRE_ARR+=("${FIRMWARE_PATH}")
    fi
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_DEEP_PRE_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_DEEP_PRE_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P60_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P60_ARR[@]}"
    detect_root_dir_helper "${LOG_DIR}/firmware"
    if [[ ${RTOS} -eq 0 ]]; then
      export NO_EXTRACTED=1
      return
    fi
  fi

  # if we run into the deep extraction mode we always do at least one extraction round:
  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 0 ]]; then
    print_output "[*] Deep extraction - ${ORANGE}1st${NC} round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 1 ]]; then
    print_output "[*] Deep extraction - ${ORANGE}2nd${NC} round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 2 ]]; then
    print_output "[*] Deep extraction - ${ORANGE}3rd${NC} round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 3 ]]; then
    print_output "[*] Deep extraction - ${ORANGE}4th${NC} round"
    print_output "[*] Walking through all files and try to extract what ever possible with unblob mode"
    print_output "[*] WARNING: This is the last extraction round that is executed."

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi
}

# deeper_extractor_helper - 深度提取辅助函数
# 功能: 遍历文件列表并调用提取器
# 参数: 无 (使用全局变量FIRMWARE_PATH_CP)
# 返回: 提取的文件保存到原目录
#
# 处理逻辑:
#   1. 使用prepare_file_arr_limited准备待处理文件列表
#   2. 遍历每个文件,计算MD5用于去重
#   3. 跳过已处理过的文件(MD5_DONE_DEEP数组)
#   4. 调用deeper_extractor_threader进行提取
#   5. 等待所有子进程完成
#
# MD5去重机制:
#   - 避免重复处理相同的文件
#   - 提高提取效率
deeper_extractor_helper() {
  local lFILE_TMP=""
  local lFILE_MD5=""
  local lFILE_DETAILS=""
  local lBIN_PID=""

  prepare_file_arr_limited "${FIRMWARE_PATH_CP}"
  print_output "[*] Deep extraction starting ..."
  for lFILE_TMP in "${FILE_ARR_LIMITED[@]}"; do
    lFILE_MD5="$(md5sum "${lFILE_TMP}")"
    [[ "${MD5_DONE_DEEP[*]}" == *"${lFILE_MD5/\ *}"* ]] && continue
    MD5_DONE_DEEP+=( "${lFILE_MD5/\ *}" )
    deeper_extractor_threader "${lFILE_TMP}" "${lFILE_MD5/\ *}" &
    lBIN_PID="$!"
    lWAIT_PIDS_P60_init+=( "${lBIN_PID}" )
    max_pids_protection $((2*"${MAX_MOD_THREADS}")) lWAIT_PIDS_P60_init
  done
  wait_for_pid "${lWAIT_PIDS_P60_init[@]}"

  cat "${LOG_PATH_MODULE}/tmp_out_"* >> "${LOG_FILE}" 2>/dev/null || true
}

# deeper_extractor_threader - 深度提取线程函数
# 功能: 针对单个文件选择合适的提取器进行提取
# 参数:
#   $1 - lFILE_TMP: 要处理的文件路径
#   $2 - lFILE_MD5: 文件的MD5值(用于日志)
# 返回: 提取的文件保存到原文件同目录
#
# 提取器选择策略 (优先级从高到低):
#   1. fw_bin_detector: 预检测固件类型
#   2. VMDK_DETECTED: VMDK虚拟机磁盘提取
#   3. EXT_IMAGE: ext文件系统提取
#   4. BSD_UFS: BSD UFS文件系统提取
#   5. ANDROID_OTA: Android OTA更新包提取
#   6. OPENSSL_ENC_DETECTED: OpenSSL加密文件提取
#   7. BUFFALO_ENC_DETECTED: Buffalo加密固件提取
#   8. ZYXEL_ZIP: ZyXel ZIP加密提取
#   9. QCOW_DETECTED: QEMU QCOW2镜像提取
#   10. BMC_ENC_DETECTED: BMC加密固件提取
#   11. 默认: 使用binwalk或unblob提取
#
# 日志处理:
#   - 每个文件的日志单独保存到 tmp_out_${MD5}.log
#   - 避免多线程日志混乱
deeper_extractor_threader() {
  local lFILE_TMP="${1:-}"
  local lFILE_MD5="${2:-}"

  local lFILE_DETAILS=""
  lFILE_DETAILS=$(file -b "${lFILE_TMP}")
  if [[ "${lFILE_DETAILS}" == *"text"* ]]; then
    return
  fi

  # to bring all the extractors to log to something we can work with,
  # we just rewrite the LOG_FILE variable in the threader now:
  export LOG_FILE="${LOG_PATH_MODULE}/tmp_out_${lFILE_MD5}"

  sub_module_title "Deep extraction of ${lFILE_TMP}"
  print_output "[*] Details of file: ${ORANGE}${lFILE_TMP}${NC}"
  print_output "$(indent "$(orange "${lFILE_DETAILS}")")"
  print_output "$(indent "$(orange "$(md5sum "${lFILE_TMP}")")")"

  # do a quick check if EMBA should handle the file or we give it to the default extractor (binwalk or unblob):
  # fw_bin_detector is a function from p02
  fw_bin_detector "${lFILE_TMP}"

  if [[ "${VMDK_DETECTED}" -eq 1 ]]; then
    vmdk_extractor "${lFILE_TMP}" "${lFILE_TMP}_vmdk_extracted"
    # now handled via unblob
    # elif [[ "${UBI_IMAGE}" -eq 1 ]]; then
    #   ubi_extractor "${lFILE_TMP}" "${lFILE_TMP}_ubi_extracted"
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 1 ]]; then
    #   dlink_SHRS_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_shrs_extracted"
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 2 ]]; then
    #   dlink_enc_img_extractor "${lFILE_TMP}" "${lFILE_TMP}_enc_img_extracted"
  elif [[ "${EXT_IMAGE}" -eq 1 ]]; then
    ext_extractor "${lFILE_TMP}" "${lFILE_TMP}_ext_extracted"
    # now handled via unblob
    # elif [[ "${ENGENIUS_ENC_DETECTED}" -ne 0 ]]; then
    #   engenius_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_engenius_extracted"
    # fi
  elif [[ "${BSD_UFS}" -ne 0 ]]; then
    ufs_extractor "${lFILE_TMP}" "${lFILE_TMP}_bsd_ufs_extracted"
  elif [[ "${ANDROID_OTA}" -ne 0 ]]; then
    android_ota_extractor "${lFILE_TMP}" "${lFILE_TMP}_android_ota_extracted"
  elif [[ "${OPENSSL_ENC_DETECTED}" -ne 0 ]]; then
    foscam_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_foscam_enc_extracted"
  elif [[ "${BUFFALO_ENC_DETECTED}" -ne 0 ]]; then
    buffalo_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_buffalo_enc_extracted"
  elif [[ "${ZYXEL_ZIP}" -ne 0 ]]; then
    zyxel_zip_extractor "${lFILE_TMP}" "${lFILE_TMP}_zyxel_enc_extracted"
  elif [[ "${QCOW_DETECTED}" -ne 0 ]]; then
    qcow_extractor "${lFILE_TMP}" "${lFILE_TMP}_qemu_qcow_extracted"
  elif [[ "${BMC_ENC_DETECTED}" -ne 0 ]]; then
    bmc_extractor "${lFILE_TMP}" "${lFILE_TMP}_bmc_decrypted"
  else
    # configure the extractor to use in the default configuration file
    # or via scanning profile
    # EMBA usually uses unblob as default for the deep extractor
    if [[ "${DEEP_EXTRACTOR}" == "binwalk" ]]; then
      binwalker_matryoshka "${lFILE_TMP}" "${lFILE_TMP}_binwalk_extracted"
    else
      # default case to Unblob
      unblobber "${lFILE_TMP}" "${lFILE_TMP}_unblob_extracted" 0
    fi
  fi
}

