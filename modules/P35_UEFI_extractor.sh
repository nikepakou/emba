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

# Description: 提取UEFI固件镜像中的内容
# 依赖工具: UEFITool, uefi-firmware-parser, BIOSUtilities (ami_pfat_extract.py), binwalk, unblob
#             - UEFITool/UEFIExtract: 用于提取UEFI固件中的文件和组件
#             - uefi-firmware-parser: Binarly开发的UEFI固件解析工具
#             - BIOSUtilities: platomav开发的BIOS/UEFI工具集，包含ami_pfat_extract.py用于提取AMI UEFI capsule
#             - binwalk: 固件分析工具，用于嵌套提取
#             - unblob: 通用固件提取工具
#
# 环境变量:
#   - UEFI_DETECTED: 标记是否检测到UEFI固件 (1=是, 0=否)
#   - RTOS: 标记是否为实时操作系统固件 (1=是, 0=否)
#   - UEFI_VERIFIED: 标记UEFI固件是否验证成功 (1=成功, 0=未验证)
#   - UEFI_AMI_CAPSULE: 标记是否检测到AMI capsule固件
#   - FILES_UEFI: 提取的UEFI文件数量
#   - FIRMWARE_PATH: 原始固件文件路径
#   - LOG_DIR: 日志输出目录
#   - P99_CSV_LOG: P99模块的CSV日志文件路径
#
# 工作流程:
#   1. 检测是否为UEFI固件 + RTOS固件
#   2. 调用uefi_firmware_parser进行初步分析
#   3. 使用UEFITool提取UEFI固件
#   4. 如检测到AMI capsule，使用ami_extractor提取
#   5. 如UEFI_VERIFIED未置位，使用unblob进行二次提取
#   6. 如仍未验证，使用binwalk进行第三次提取
#   7. 对所有提取的文件进行架构分析

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
export PRE_THREAD_ENA=0

# P35_UEFI_extractor - UEFI固件提取主函数
# 功能: 协调多种UEFI固件提取工具，对UEFI/RTOS固件进行全面提取
# 参数: 无 (使用全局环境变量)
# 返回: lNEG_LOG - 提取结果标志 (0=未提取到有效内容, 1=成功提取)
#
# 提取策略 (优先级从高到低):
#   1. UEFITool提取 - 首选UEFI标准工具
#   2. AMI Extractor - 检测到AMI capsule时使用
#   3. Unblob提取 - 作为备选方案
#   4. Binwalk提取 - 最后备选方案
#
# 关键逻辑:
#   - 只有当UEFI_DETECTED=1且RTOS=1时才运行此模块
#   - 每种提取方式后都会检查UEFI_VERIFIED标志
#   - 一旦UEFI_VERIFIED=1或RTOS=0(检测到Linux文件系统),停止进一步提取
#   - 对提取的每个文件调用binary_architecture_threader进行架构分析
P35_UEFI_extractor() {
  local lNEG_LOG=0

  if [[ "${UEFI_DETECTED}" -eq 1 && "${RTOS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UEFI extraction module"
    pre_module_reporter "${FUNCNAME[0]}"
    export FILES_UEFI=0

    if [[ -d "${FIRMWARE_PATH}" ]]; then
      # as we currently handle only firmware files in the UEFI extraction module
      # we need to work with the original firmware file - if this is also a directory
      # or we already have a linux filesytem we can exit now
      detect_root_dir_helper "${FIRMWARE_PATH}"

      FIRMWARE_PATH="${FIRMWARE_PATH_BAK}"
      if [[ -d "${FIRMWARE_PATH}" || "${RTOS}" -ne 1 ]]; then
        # we exit the module now
        module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
        return
      fi
    fi

    local lFW_NAME_=""
    lFW_NAME_="$(basename "${FIRMWARE_PATH}")"

    uefi_firmware_parser "${FIRMWARE_PATH}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${lFW_NAME_}"
    uefi_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"
    if [[ "${UEFI_AMI_CAPSULE}" -gt 0 ]]; then
      lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_ami_capsule_"${lFW_NAME_}"
      ami_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 ]]; then
      # do a second round with unblob
      lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${lFW_NAME_}"_unblob_extracted
      unblobber "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}" 0

      mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR}" -type f ! -name "*.raw")

      print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from UEFI firmware image in Unblob mode."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      detect_root_dir_helper "${lEXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${lEXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        # lets check for UEFI firmware
        local lTMP_UEFI_FILES_ARR=()
        local lUEFI_FILE=""
        mapfile -t lTMP_UEFI_FILES_ARR < <(grep "^${FUNCNAME[0]};" "${P99_CSV_LOG}" | cut -d ';' -f2 | grep "${lEXTRACTION_DIR}" | sort -u)
        for lUEFI_FILE in "${lTMP_UEFI_FILES_ARR[@]}"; do
          uefi_firmware_parser "${lUEFI_FILE}"
          if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
            lNEG_LOG=1
            break
          fi
        done
        if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
          # if we have no UEFI firmware and no Linux filesystem, we remove this file junks now
          rm -rf "${lEXTRACTION_DIR}" || true
        fi
      fi
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
      # do an additional backup round with binwalk
      # e.g. https://ftp.hp.com/pub/softpaq/sp148001-148500/sp148108.exe
      lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${lFW_NAME_}"_binwalk_extracted
      binwalker_matryoshka "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

      mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR}" -type f ! -name "*.raw")

      print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from UEFI firmware image in Binwalk mode."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      detect_root_dir_helper "${lEXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${lEXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        local lTMP_UEFI_FILES_ARR=()
        local lUEFI_FILE=""
        mapfile -t lTMP_UEFI_FILES_ARR < <(grep "^${FUNCNAME[0]};" "${P99_CSV_LOG}" | cut -d ';' -f2 | grep "${lEXTRACTION_DIR}" | sort -u)
        for lUEFI_FILE in "${lTMP_UEFI_FILES_ARR[@]}"; do
          uefi_firmware_parser "${lUEFI_FILE}"
          if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
            lNEG_LOG=1
            break
          fi
        done
        if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
          # if we have no UEFI firmware and no Linux filesystem, we remove this file junks now
          rm -rf "${lEXTRACTION_DIR}" || true
        fi
      fi
    fi

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      lNEG_LOG=1
    fi
    if [[ "${UEFI_VERIFIED}" -eq 1 || "${RTOS}" -eq 0 ]]; then
      lNEG_LOG=1
    fi

    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

# uefi_firmware_parser - UEFI固件解析函数
# 功能: 使用Binarly的uefi-firmware-parser工具分析UEFI固件结构
# 参数: 
#   $1 - lFIRMWARE_PATH_: 要分析的固件文件路径
# 返回: 输出解析结果到日志文件,设置UEFI_VERIFIED全局变量
#
# 依赖工具: uefi-firmware-parser (Binarly开发)
#   - 官方网站: https://github.com/binarly-io/uefi-firmware-parser
#   - 功能: 解析UEFI固件卷(Firmware Volume),提取PE/EFI镜像
#
# 输出:
#   - 解析结果保存到 ${LOG_PATH_MODULE}/uefi-firmware-parser_${lFW_NAME_}.txt
#   - 如果检测到多个Firmware Volume,设置UEFI_VERIFIED=1
uefi_firmware_parser() {
  sub_module_title "UEFI firmware-parser analysis"
  local lFIRMWARE_PATH_="${1:-}"
  local lFW_NAME_=""
  if [[ ! -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] UEFI firmware analysis for file ${lFIRMWARE_PATH_} not possible"
    return
  fi
  lFW_NAME_="$(basename "${lFIRMWARE_PATH_}")"

  uefi-firmware-parser -b "${lFIRMWARE_PATH_}" > "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt

  if [[ -s "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt ]]; then
    print_ln
    print_output "[*] UEFI firmware parser results for ${lFW_NAME_}." "" "${LOG_PATH_MODULE}/uefi-firmware-parser_${lFW_NAME_}.txt"
    cat "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt
    print_ln

    if [[ "$(grep -c "Found volume magic at \|Firmware Volume:" "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt)" -gt 1 ]]; then
      # with UEFI_VERIFIED=1 we do not further run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from UEFI firmware-parser for ${ORANGE}${lFIRMWARE_PATH_}${NC}." "no_log"
  fi
}

# ami_extractor - AMI UEFI Capsule提取器
# 功能: 使用BIOSUtilities中的ami_pfat_extract.py提取AMI UEFI capsule固件
# 参数:
#   $1 - lFIRMWARE_PATH_: 原始固件文件路径
#   $2 - lEXTRACTION_DIR_: 提取输出目录
# 返回: 提取的固件保存到指定目录,更新CSV日志
#
# 依赖工具: ami_pfat_extract.py (BIOSUtilities)
#   - 官方网站: https://github.com/platomav/BIOSUtilities
#   - 用途: 提取AMI PFAT (Pre-Flash Authentication Technology) capsule固件
#   - 支持的固件类型: AMI Aptio UEFI固件
#
# 提取流程:
#   1. 运行ami_pfat_extract.py进行提取
#   2. 检查提取结果是否有效(无Error输出)
#   3. 对提取的文件进行架构分析
#   4. 如果提取文件数>5,设置UEFI_VERIFIED=1跳过深度提取
#   5. 写入CSV日志记录提取结果
ami_extractor() {
  sub_module_title "AMI capsule UEFI extractor"

  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lDIRS_UEFI=0
  local lFIRMWARE_NAME_=""

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  lFIRMWARE_NAME_="$(basename "${lFIRMWARE_PATH_}")"

  echo -ne '\n' | python3 "${EXT_DIR}"/BIOSUtilities/biosutilities/ami_pfat_extract.py -o "${lEXTRACTION_DIR_}" "${lFIRMWARE_PATH_}" &> "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log || true

  if [[ -s "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log ]] && ! grep -q "Error: " "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log

    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
    find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln

    mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
    print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from the firmware image."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P35_UEFI_extractor" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "UEFI AMI extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_UEFI}" "NA"

    if [[ "${#lFILES_UEFI_ARR[@]}" -gt 5 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from AMI capsule UEFI extractor"
  fi
  print_ln
}

# uefi_extractor - UEFITool提取器
# 功能: 使用UEFITool提取UEFI固件中的所有组件
# 参数:
#   $1 - lFIRMWARE_PATH_: 原始固件文件路径
#   $2 - lEXTRACTION_DIR_: 提取输出目录
# 返回: 提取的固件组件保存到指定目录,输出详细报告
#
# 依赖工具: UEFIExtract (UEFITool子工具)
#   - 官方网站: https://github.com/LongSoft/UEFITool
#   - 用途: 提取和解包UEFI固件中的所有组件
#   - 支持: PE32镜像、DXE驱动、NVAR变量等
#
# 提取内容:
#   - NVAR entry: UEFI NVRAM变量条目
#   - PE32 image: 32位PE可执行镜像
#   - DXE driver: DXE驱动程序
#
# 输出报告:
#   - firmware.report.txt: 包含所有提取组件的详细信息
#   - 统计提取的NVAR/PE32/驱动数量
#   - 尝试检测UEFI架构类型(x64/IA32/ARM等)
uefi_extractor() {
  sub_module_title "UEFITool extractor"

  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"

  local lFIRMWARE_NAME_=""
  local lUEFI_EXTRACT_REPORT_FILE=""

  local lUEFI_EXTRACT_BIN="${EXT_DIR}""/UEFITool/UEFIExtract"
  local lDIRS_UEFI=0
  local lNVARS=0
  local lPE32_IMAGE=0
  local lDRIVER_COUNT=0
  local lEFI_ARCH=""

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  lFIRMWARE_NAME_="$(basename "${lFIRMWARE_PATH_}")"
  if ! [[ -d "${lEXTRACTION_DIR_}" ]]; then
    mkdir -p "${lEXTRACTION_DIR_}"
  fi
  cp "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}"
  "${lUEFI_EXTRACT_BIN}" "${lEXTRACTION_DIR_}"/firmware all &> "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log || print_error "[-] UEFI firmware extraction failed"

  lUEFI_EXTRACT_REPORT_FILE="${lEXTRACTION_DIR_}"/firmware.report.txt
  if [[ -f "${lUEFI_EXTRACT_REPORT_FILE}" ]]; then
    mv "${lUEFI_EXTRACT_REPORT_FILE}" "${LOG_PATH_MODULE}"
    lUEFI_EXTRACT_REPORT_FILE="${LOG_PATH_MODULE}"/firmware.report.txt
  else
    print_output "[-] UEFI firmware extraction failed" "no_log"
    return
  fi

  if [[ -f "${lEXTRACTION_DIR_}"/firmware ]]; then
    rm "${lEXTRACTION_DIR_}"/firmware
  fi

  if [[ -f "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log ]]; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log
    if grep -q "parse: not a single Volume Top File is found, the image may be corrupted" "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log; then
      print_output "[-] No results from UEFITool UEFI Extractor"
      return
    fi
  fi

  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}/firmware.dump${NC}) as base directory:"
  find "${lEXTRACTION_DIR_}"/firmware.dump -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln

  lNVARS=$(grep -c "NVAR entry" "${lUEFI_EXTRACT_REPORT_FILE}" || true)
  lPE32_IMAGE=$(grep -c "PE32 image" "${lUEFI_EXTRACT_REPORT_FILE}" || true)
  lDRIVER_COUNT=$(grep -c "DXE driver" "${lUEFI_EXTRACT_REPORT_FILE}" || true)

  mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")

  print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from UEFI firmware image."
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

  for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
    binary_architecture_threader "${lBINARY}" "P35_UEFI_extractor" &
    local lTMP_PID="$!"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  lEFI_ARCH=$(find "${lEXTRACTION_DIR_}" -name "info.txt" -exec grep "Machine type" {} \; | sort -u | sed -E 's/Machine\ type\:\ //g' | head -n 1)

  print_output "[*] Found ${ORANGE}${lNVARS}${NC} NVARS and ${ORANGE}${lDRIVER_COUNT}${NC} drivers."
  if [[ -n "${lEFI_ARCH}" ]]; then
    print_output "[*] Found ${ORANGE}${lPE32_IMAGE}${NC} PE32 images for architecture ${ORANGE}${lEFI_ARCH}${NC} drivers."
    print_output "[+] Possible architecture details found (${ORANGE}UEFI Extractor${GREEN}): ${ORANGE}${lEFI_ARCH}${NC}"
    backup_var "EFI_ARCH" "${lEFI_ARCH}"
    if [[ "${FILES_UEFI}" -gt 0 ]] && [[ "${lDIRS_UEFI}" -gt 0 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  fi

  print_ln

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "UEFI architecture"
  write_csv_log "UEFITool extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_UEFI}" "${lDIRS_UEFI}" "${lEFI_ARCH}"
}
