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

# Description: 固件文件初步分析和类型检测
# 依赖工具: file, sha512sum, sha1sum, md5sum, ent, hexdump, strings, binwalk
#             - file: 文件类型识别
#             - sha512sum/sha1sum/md5sum: 校验和计算
#             - ent: 信息熵计算
#             - hexdump: 十六进制查看
#             - strings: 提取字符串
#             - binwalk: 固件分析工具
#             - pixde: 可视化固件工具
#
# 环境变量:
#   - UEFI_DETECTED: UEFI固件检测标志
#   - VMDK_DETECTED: VMware VMDK镜像检测
#   - UBI_IMAGE: UBI文件系统检测
#   - DLINK_ENC_DETECTED: D-Link加密固件检测
#   - ENGENIUS_ENC_DETECTED: EnGenius加密固件检测
#   - QNAP_ENC_DETECTED: QNAP加密固件检测
#   - GPG_COMPRESS: GPG压缩固件检测
#   - BSD_UFS: BSD UFS文件系统检测
#   - EXT_IMAGE: ext2/3/4文件系统检测
#   - OPENSSL_ENC_DETECTED: OpenSSL加密检测
#   - BUFFALO_ENC_DETECTED: Buffalo加密固件检测
#   - ZYXEL_ZIP: ZyXel加密ZIP检测
#   - QCOW_DETECTED: QEMU QCOW镜像检测
#   - UBOOT_IMAGE: U-Boot镜像检测
#   - DJI_XV4_DETECTED: 大疆xV4固件检测
#   - DJI_PRAK_DETECTED: 大疆PRAK固件检测
#   - WINDOWS_EXE: Windows可执行文件检测
#   - ANDROID_OTA: Android OTA更新包检测
#   - AVM_DETECTED: AVM固件检测
#   - BMC_ENC_DETECTED: BMC加密固件检测
#
# 模块定位:
#   - P阶段第2个模块(P02)
#   - 在P01之后运行,负责固件文件的初步分析
#   - 识别固件类型,设置相应的检测标志
#   - 为后续专用提取模块提供依据
#
# 检测的固件类型:
#   - 压缩格式: gzip, zip, tar, iso, xz, bzip2, 7-zip
#   - 文件系统: UBI, ext2/3/4, UFS, QCOW2
#   - 虚拟机: VMDK, QEMU QCOW
#   - 加密固件: D-Link, EnGenius, QNAP, Buffalo, ZyXel, BMC
#   - 无人机: DJI xV4, DJI PRAK
#   - 其他: UEFI/BIOS, U-Boot, Android OTA, GPG压缩
#   - 脚本语言: Perl, PHP, Python, Shell
#   - 安装包: DEB, RPM, JAR, APK, Windows EXE

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
export PRE_THREAD_ENA=0

# P02_firmware_bin_file_check - 固件文件分析主函数
# 功能: 对提供的固件进行初步分析和类型识别
# 参数: 无 (使用全局环境变量FIRMWARE_PATH)
# 返回: 设置各类固件检测标志,输出分析日志
#
# 分析流程:
#   1. 初始化默认导出变量(set_p02_default_exports)
#   2. 如果输入是目录,设置FIRMWARE_PATH为日志目录
#   3. 如果是文件,获取文件详情(get_fw_file_details)
#   4. 生成熵值图(generate_entropy_graph)
#   5. 如果是目录,获取目录详情(get_fw_dir_details)
#   6. 打印文件详情(print_fw_file_details)
#   7. 生成pixde可视化(generate_pixde)
#   8. 执行固件类型检测(fw_bin_detector)
#   9. 备份P02相关变量(backup_p02_vars)
P02_firmware_bin_file_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware file analyzer"
  pre_module_reporter "${FUNCNAME[0]}"
  set_p02_default_exports

  # we set this var global to 1 if we find something UEFI related
  export UEFI_DETECTED=0

  write_csv_log "Entity" "data" "Notes"
  write_csv_log "Firmware path" "${FIRMWARE_PATH}" "NA"

  if [[ -d "${FIRMWARE_PATH}" ]]; then
    export FIRMWARE_PATH="${LOG_DIR}"/firmware/
  fi

  if [[ -f "${FIRMWARE_PATH}" ]] && [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    get_fw_file_details "${FIRMWARE_PATH}"
    generate_entropy_graph "${FIRMWARE_PATH}"
  elif [[ -d "${FIRMWARE_PATH}" ]] && [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    get_fw_dir_details "${FIRMWARE_PATH}"
  fi

  local lFILE_LS_OUT=""
  lFILE_LS_OUT=$(ls -lh "${FIRMWARE_PATH}")

  print_ln
  print_output "[*] Details of the firmware file:"
  print_output "$(indent "${lFILE_LS_OUT}")"
  if [[ -f "${FIRMWARE_PATH}" ]]; then
    if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
      print_fw_file_details "${FIRMWARE_PATH}"
      generate_pixde "${FIRMWARE_PATH}"
    fi
    fw_bin_detector "${FIRMWARE_PATH}"
    backup_p02_vars
  fi

  module_end_log "${FUNCNAME[0]}" 1
}

# get_fw_dir_details - 固件目录详情获取函数
# 功能: 计算固件目录中所有文件的MD5哈希
# 参数:
#   $1 - lFIRMWARE_PATH_DIR: 固件目录路径
# 返回: 生成firmware_hashes.log用于重启检查
#
# 用途: 
#   - 用于EMBA重启时判断固件是否已更改
#   - 如果MD5列表一致,可复用之前的分析结果
get_fw_dir_details() {
  local lFIRMWARE_PATH_DIR="${1:-}"
  # we create a log file with all file hashes of the firmware directory
  # this is needed to check the firmware directory on a possible restart against this
  # file and decide if we can restart a firmware analysis process or not
  find "${lFIRMWARE_PATH_DIR}" -type f -exec md5sum {} \; | sort -u | awk '{print $1}' > "${LOG_PATH_MODULE}/firmware_hashes.log" || true
}

# get_fw_file_details - 固件文件详情获取函数
# 功能: 计算固件文件的校验和信息
# 参数:
#   $1 - lFIRMWARE_PATH_BIN: 固件文件路径
# 返回: 计算SHA512/SHA1/MD5和熵值,写入CSV日志
#
# 计算内容:
#   - SHA512校验和
#   - SHA1校验和
#   - MD5校验和
#   - 信息熵(使用ent工具)
get_fw_file_details() {
  local lFIRMWARE_PATH_BIN="${1:-}"

  SHA512_CHECKSUM="$(sha512sum "${lFIRMWARE_PATH_BIN}" | awk '{print $1}')"
  write_csv_log "SHA512" "${SHA512_CHECKSUM:-}" "NA"
  SHA1_CHECKSUM="$(sha1sum "${lFIRMWARE_PATH_BIN}" | awk '{print $1}')"
  write_csv_log "SHA1" "${SHA1_CHECKSUM:-}" "NA"
  MD5_CHECKSUM="$(md5sum "${lFIRMWARE_PATH_BIN}" | awk '{print $1}')"
  write_csv_log "MD5" "${MD5_CHECKSUM:-}" "NA"

  # 使用 ent 工具计算固件文件的熵值
  # 1.判断数据是否加密或压缩
  #   高熵值（接近8）：数据可能是加密或压缩的
  #   低熵值（接近0）：数据可能是明文或未压缩的
  # 2.识别固件中的不同区域
  #   代码区域：中等熵值
  #   数据区域：低熵值
  #   加密/压缩区域：高熵值
  ENTROPY="$(ent "${lFIRMWARE_PATH_BIN}" | grep Entropy | sed -e 's/^Entropy\ \=\ //')"
  write_csv_log "Entropy" "${ENTROPY:-}" "NA"
}

# print_fw_file_details - 固件文件详情打印函数
# 功能: 输出固件文件的详细信息
# 参数:
#   $1 - lFIRMWARE_PATH_BIN: 固件文件路径
# 返回: 输出到日志和终端
#
# 输出内容:
#   - file命令识别结果
#   - 文件头部十六进制预览
#   - SHA512校验和
#   - 信息熵值
print_fw_file_details() {
  local lFIRMWARE_PATH_BIN="${1:-}"

  print_output "$(indent "$(file "${lFIRMWARE_PATH_BIN}")")"
  print_ln
  hexdump -C "${lFIRMWARE_PATH_BIN}"| head | tee -a "${LOG_FILE}" || true
  print_ln
  print_output "[*] SHA512 checksum: ${ORANGE}${SHA512_CHECKSUM}${NC}"
  print_ln
  print_output "[*] Entropy of firmware file:"
  print_output "$(indent "${ENTROPY}")"
  print_ln
}

# generate_pixde - 固件可视化函数
# 功能: 使用pixde工具生成固件的可视化图像
# 参数:
#   $1 - lFIRMWARE_PATH_BIN: 固件文件路径
# 返回: 生成pixd.png可视化图像
#
# 依赖工具: pixde, pixd_png.py
#   - pixde: 固件可视化工具,显示二进制数据的结构
#   - pixd_png.py: 将pixde输出转换为PNG图像
#
# 可视化范围: 固件前2000字节
generate_pixde() {
  local lFIRMWARE_PATH_BIN="${1:-}"
  local lPIXD_PNG_PATH="${LOG_DIR}"/pixd.png

  if [[ -x "${EXT_DIR}"/pixde ]]; then
    print_output "[*] Visualized firmware file (first 2000 bytes):"
    print_ln "no_log"
    "${EXT_DIR}"/pixde -r-0x2000 "${lFIRMWARE_PATH_BIN}" | tee -a "${LOG_DIR}"/p02_pixd.txt
    python3 "${EXT_DIR}"/pixd_png.py -i "${LOG_DIR}"/p02_pixd.txt -o "${lPIXD_PNG_PATH}" -p 10 > /dev/null
    write_link "${lPIXD_PNG_PATH}"
    print_ln "no_log"
  fi
}

# set_p02_default_exports - P02模块默认变量初始化函数
# 功能: 初始化所有P02相关的检测标志变量
# 参数: 无
# 返回: 设置所有相关全局变量为默认值0
#
# 初始化的变量:
#   - SHA512_CHECKSUM, SHA1_CHECKSUM, MD5_CHECKSUM, ENTROPY
#   - DLINK_ENC_DETECTED, VMDK_DETECTED, UBOOT_IMAGE, EXT_IMAGE
#   - AVM_DETECTED, BMC_ENC_DETECTED, UBI_IMAGE, OPENSSL_ENC_DETECTED
#   - ENGENIUS_ENC_DETECTED, BUFFALO_ENC_DETECTED, QNAP_ENC_DETECTED
#   - GPG_COMPRESS, BSD_UFS, ANDROID_OTA, UEFI_AMI_CAPSULE
#   - ZYXEL_ZIP, QCOW_DETECTED, UEFI_VERIFIED
#   - DJI_PRAK_DETECTED, DJI_XV4_DETECTED, WINDOWS_EXE
set_p02_default_exports() {
  export SHA512_CHECKSUM="NA"
  export SHA1_CHECKSUM="NA"
  export MD5_CHECKSUM="NA"
  export ENTROPY="NA"
  export DLINK_ENC_DETECTED=0
  export VMDK_DETECTED=0
  export UBOOT_IMAGE=0
  export EXT_IMAGE=0
  export AVM_DETECTED=0
  export BMC_ENC_DETECTED=0
  export UBI_IMAGE=0
  export OPENSSL_ENC_DETECTED=0
  export ENGENIUS_ENC_DETECTED=0
  export BUFFALO_ENC_DETECTED=0
  export QNAP_ENC_DETECTED=0
  export GPG_COMPRESS=0
  export BSD_UFS=0
  export ANDROID_OTA=0
  # Note: we do not set UEFI_DETECTED in this function. If so, we are going to reset it and we only need
  #       an indicator if this could be some UEFI firmware for further processing
  export UEFI_AMI_CAPSULE=0
  export ZYXEL_ZIP=0
  export QCOW_DETECTED=0
  export UEFI_VERIFIED=0
  export DJI_PRAK_DETECTED=0
  export DJI_XV4_DETECTED=0
  export WINDOWS_EXE=0
}

# generate_entropy_graph - 熵值图生成函数
# 功能: 使用binwalk生成固件的信息熵图形化
# 参数:
#   $1 - lFIRMWARE_PATH_BIN: 固件文件路径
# 返回: 生成firmware_entropy.png熵值图
#
# 熵值分析:
#   - 熵值接近0: 可能是全零填充或重复数据
#   - 熵值接近1: 可能是加密或压缩数据
#   - 熵值0.5-0.7: 可能是正常代码/数据混合
#   - 用于识别固件中的加密/压缩区域
generate_entropy_graph() {
  local lFIRMWARE_PATH_BIN="${1:-}"
  local lENTROPY_PIC_PATH="${LOG_DIR}/firmware_entropy.png"

  # we use the original FIRMWARE_PATH for entropy testing, just if it is a file
  if [[ -f "${lFIRMWARE_PATH_BIN}" ]] && ! [[ -f "${lENTROPY_PIC_PATH}" ]]; then
    print_output "[*] Entropy testing with binwalk ... "
    print_output "$("${BINWALK_BIN[@]}" -E -p "${lENTROPY_PIC_PATH}" "${lFIRMWARE_PATH_BIN}")"
    if [[ -s "${lENTROPY_PIC_PATH}" ]]; then
      write_link "${lENTROPY_PIC_PATH}"
    fi
  fi
}

# fw_bin_detector - 固件类型检测核心函数
# 功能: 通过文件特征、字符串和binwalk分析识别固件类型
# 参数:
#   $1 - lCHECK_FILE: 要检测的文件路径
# 返回: 设置相应的固件检测标志
#
# 检测方法:
#   1. file命令识别文件类型
#   2. hexdump查看文件头特征
#   3. strings提取字符串特征
#   4. binwalk分析内容
#
# 检测的固件类型:
#   - BMC加密: 检测libipmi.so字符串
#   - DJI PRAK: 检测PRAK/RREK/IAEK/PUEK字符串
#   - DJI xV4: 检测x78x56x34魔数
#   - AVM固件: 检测AVM GmbH字符串
#   - QNAP加密: 检测"qnap encrypted"
#   - UEFI/BIOS: 检测UEFI/BIOS字符串
#   - VMware VMDK: 检测VMware4磁盘镜像
#   - UBI文件系统: 检测UBI image
#   - D-Link SHRS: 检测SHRS文件头
#   - EnGenius: 检测特定文件头模式
#   - U-Boot: 检测u-boot legacy uImage
#   - BSD UFS: 检测Unix Fast File system
#   - ext文件系统: 检测Linux ext2/3/4 filesystem
#   - QEMU QCOW: 检测QEMU QCOW2 Image
#   - GPG压缩: 检测a3x01文件头+gpg包
#   - Android OTA: 检测CrAU文件头
#   - OpenSSL加密: 检测openssl enc'd data
#   - Buffalo加密: 检测bgn文件头
#   - ZyXel: 检测.ri文件和对应.bin
#   - 脚本语言: Perl/PHP/Python/Shell脚本
#   - 安装包: DEB/RPM/JAR/APK/MSI/Windows EXE
fw_bin_detector() {
  local lCHECK_FILE="${1:-}"
  local lCHECK_FILE_NAME=""
  lCHECK_FILE_NAME="$(basename "${lCHECK_FILE}")"
  local lFILE_BIN_OUT=""
  local lHEX_FIRST_LINE=""
  local lQNAP_ENC_CHECK=""
  local lAVM_CHECK=0
  local lUEFI_CHECK=0
  local lDJI_PRAK_ENC_CHECK=0
  local lDJI_XV4_ENC_CHECK=0
  local lBMC_CHECK=0
  local lGPG_CHECK=0

  set_p02_default_exports

  # 使用 strings 命令提取文件中的可打印字符串，保存到日志文件
  # 后台运行以提高效率，同时获取进程ID用于等待
  strings "${lCHECK_FILE}" > "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" &
  local lTMP_PID="$!"  # 获取 strings 命令的进程ID

  # 使用 file 命令识别文件类型，返回如 "ELF", "gzip compressed data" 等信息
  lFILE_BIN_OUT=$(file "${lCHECK_FILE}")

  # 使用 hexdump 以可读格式显示文件的前16字节内容，提取第一行用于魔数识别
  # -C 参数：以十六进制+ASCII格式显示，便于识别文件头
  # head -1：只取第一行，即文件开头
  lHEX_FIRST_LINE=$(hexdump -C "${lCHECK_FILE}" | head -1 || true)

  # 等待 strings 命令后台任务完成，确保字符串提取完成后再继续
  wait_for_pid "${lTMP_PID}"

  # 检查AVM固件特征：搜索AVM GmbH版权字符串
  # grep -c：统计匹配的行数
  # 支持两种格式："AVM GmbH ... All rights reserved." 和 "(C) Copyright ... AVM"
  lAVM_CHECK=$(grep -c "AVM GmbH .*. All rights reserved.\|(C) Copyright .* AVM" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)

  # 检查Supermicro BMC固件特征：搜索 libipmi.so 字符串
  # libipmi.so 是智能平台管理接口(IPMI)库，BMC固件的典型组件
  lBMC_CHECK=$(grep -c "libipmi.so" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)

  # SBOM_MINIMAL模式检查：如果不是最小SBOM模式，则执行详细分析
  if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    # 检查大疆PRAK加密固件：搜索加密密钥相关字符串
    # PRAK/RREK/IAEK/PUEK是大疆固件加密使用的密钥类型标识
    lDJI_PRAK_ENC_CHECK=$(grep -c "PRAK\|RREK\|IAEK\|PUEK" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)

    # 检查大疆XV4加密固件：搜索特定的十六进制模式 0x785634
    # grep -b：在二进制文件中搜索匹配的位置
    # grep -o：只输出匹配的部分
    # grep -U：将内容视为二进制数据
    # grep -a：将二进制文件当作文本处理
    # grep -P：使用Perl正则表达式
    lDJI_XV4_ENC_CHECK=$(grep -boUaP "\x78\x56\x34" "${lCHECK_FILE}" | grep -c "^0:"|| true)

    # 运行 binwalk 工具分析固件文件，识别文件系统、内核、压缩数据等
    # 将完整输出保存到日志文件供后续分析
    # we are running binwalk on the file to analyze the output afterwards:
    "${BINWALK_BIN[@]}" "${lCHECK_FILE}" > "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true

    # 检查威联通(QNAP)加密固件
    if [[ -f "${LOG_PATH_MODULE}"/p02_binwalk_output.txt ]]; then
      # 方法1：从binwalk输出文件中搜索"qnap encrypted"字符串
      lQNAP_ENC_CHECK=$(grep -a -i "qnap encrypted" "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true)
    else
      # 方法2：binwalk输出文件不存在时，直接使用binwalk的-y选项搜索
      lQNAP_ENC_CHECK=$("${BINWALK_BIN[@]}" -y "qnap encrypted" "${lCHECK_FILE}")
    fi

    # 检查UEFI/BIOS固件特征（初步检测）
    # the following check is very weak. It should be only an indicator if the firmware could be a UEFI/BIOS firmware
    # further checks will follow in P35
    # 从binwalk输出中搜索UEFI或BIOS字符串
    lUEFI_CHECK=$(grep -c "UEFI\|BIOS" "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true)
    # 从strings输出中搜索UEFI或BIOS字符串，累加匹配次数
    lUEFI_CHECK=$(("${lUEFI_CHECK}" + "$(grep -c "UEFI\|BIOS" "${LOG_PATH_MODULE}/strings_${lCHECK_FILE_NAME}.txt" || true)" ))
  fi

  if [[ -f "${KERNEL_CONFIG}" ]] && [[ "${KERNEL}" -eq 1 ]]; then
    # we set the FIRMWARE_PATH to the kernel config path if we have only -k parameter
    if [[ "$(md5sum "${KERNEL_CONFIG}" | awk '{print $1}')" == "$(md5sum "${FIRMWARE_PATH}" | awk '{print $1}')" ]]; then
      print_output "[+] Identified Linux kernel configuration file"
      write_csv_log "kernel config" "yes" "NA"
      export SKIP_PRE_CHECKERS=1
      # for the kernel configuration only test we only need module s25
      export SELECT_MODULES=( "S25" )
      return
    fi
  fi

  if [[ "${lBMC_CHECK}" -gt 0 ]]; then
    print_output "[+] Identified possible Supermicro BMC encrpyted firmware - using BMC extraction module"
    export BMC_ENC_DETECTED=1
    write_csv_log "BMC encrypted" "yes" "NA"
  fi
  if [[ "${lDJI_PRAK_ENC_CHECK}" -gt 0 ]]; then
    if file "${FIRMWARE_PATH}" | grep -q "POSIX tar archive"; then
      print_output "[+] Identified possible DJI PRAK drone firmware - using DJI extraction module"
      DJI_PRAK_DETECTED=1
      # UEFI is FP and we reset it now
      lUEFI_CHECK=0
      write_csv_log "DJI-PRAK" "yes" "tar compressed"
    fi
  fi
  if [[ "${lDJI_XV4_ENC_CHECK}" -gt 0 ]]; then
    print_output "[+] Identified possible DJI xV4 drone firmware - using DJI extraction module"
    DJI_XV4_DETECTED=1
    # UEFI is FP and we reset it now
    lUEFI_CHECK=0
    write_csv_log "DJI-xV4" "yes" "NA"
  fi
  if [[ "${lAVM_CHECK}" -gt 0 ]] || [[ "${FW_VENDOR}" == *"AVM"* ]]; then
    print_output "[+] Identified AVM firmware."
    export AVM_DETECTED=1
    write_csv_log "AVM firmware detected" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"gzip compressed data"* || "${lFILE_BIN_OUT}" == *"Zip archive data"* || \
    "${lFILE_BIN_OUT}" == *"POSIX tar archive"* || "${lFILE_BIN_OUT}" == *"ISO 9660 CD-ROM filesystem data"* || \
    "${lFILE_BIN_OUT}" == *"7-zip archive data"* || "${lFILE_BIN_OUT}" == *"XZ compressed data"* || \
    "${lFILE_BIN_OUT}" == *"bzip2 compressed data"* ]]; then
    # as the AVM images are also zip files we need to bypass it here:
    if [[ "${AVM_DETECTED}" -ne 1 ]]; then
      print_output "[+] Identified gzip/zip/tar/iso/xz/bzip2 archive file"
      write_csv_log "basic compressed" "yes" "NA"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"QEMU QCOW2 Image"* ]] || [[ "${lFILE_BIN_OUT}" == *"QEMU QCOW Image"* ]]; then
    print_output "[+] Identified Qemu QCOW image - using QCOW extraction module"
    export QCOW_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "Qemu QCOW firmware detected" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Debian binary package"* ]]; then
    print_output "[+] Identified Debian package archive file - using package extraction module"
    cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.deb" || print_error "[-] Deb package copy process failed"
    write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.deb" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    export DISABLE_DEEP=1
    write_csv_log "DEB" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Java archive data"* ]]; then
    print_output "[+] Identified Java archive package - using package extraction module"
    cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.jar" || print_error "[-] Java archive copy process failed"
    write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.jar" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    export DISABLE_DEEP=1
    write_csv_log "JAR" "yes" "NA"
  fi

  if [[ "${lFILE_BIN_OUT}" == *"RPM v3.0 bin"* ]]; then
    print_output "[+] Identified RPM package archive file - using package extraction module"
    cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.rpm" || print_error "[-] RPM package copy process failed"
    write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.rpm" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    export DISABLE_DEEP=1
    write_csv_log "RPM" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"VMware4 disk image"* ]]; then
    print_output "[+] Identified VMWware VMDK archive file - using VMDK extraction module"
    export VMDK_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "VMDK" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"UBI image"* ]]; then
    print_output "[+] Identified UBI filesystem image - using UBI extraction module"
    export UBI_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "UBI filesystem" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" == *"SHRS"* ]]; then
    print_output "[+] Identified D-Link SHRS encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "D-Link SHRS" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 0.\ ..\ \ 00\ 00\ 0.\ ..\ 31\ 32\ 33\ 00 ]]; then
    print_output "[+] Identified EnGenius encrpyted firmware - using EnGenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "EnGenius encrypted" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 01\ 01\ \ 00\ 00\ 0.\ ..\ 33\ 2e\ 3[89]\ 2e ]]; then
    print_output "[+] Identified EnGenius encrpyted firmware - using EnGenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "EnGenius encrypted" "yes" "NA"
  fi
  if [[ "${lHEX_FIRST_LINE}" == *"encrpted_img"* ]]; then
    print_output "[+] Identified D-Link encrpted_img encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=2
    lUEFI_CHECK=0
    write_csv_log "D-Link encrpted_img encrypted" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"u-boot legacy uImage"* ]]; then
    print_output "[+] Identified u-boot firmware image"
    export UBOOT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "Uboot image" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Unix Fast File system [v2]"* ]]; then
    print_output "[+] Identified UFS filesytem - using UFS filesytem extraction module"
    export BSD_UFS=1
    lUEFI_CHECK=0
    write_csv_log "BSD UFS filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Linux rev 1.0 ext2 filesystem data"* ]]; then
    print_output "[+] Identified Linux ext2 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "EXT2 filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Linux rev 1.0 ext3 filesystem data"* ]]; then
    print_output "[+] Identified Linux ext3 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "EXT3 filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Linux rev 1.0 ext4 filesystem data"* ]]; then
    print_output "[+] Identified Linux ext4 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    lUEFI_CHECK=0
    write_csv_log "EXT4 filesystem" "yes" "NA"
  fi
  if [[ "${lQNAP_ENC_CHECK}" == *"QNAP encrypted firmware footer , model"* ]]; then
    print_output "[+] Identified QNAP encrpyted firmware - using QNAP extraction module"
    export QNAP_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "QNAP encrypted filesystem" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"ELF"* ]]; then
    # looks like we have only and ELF file to test
    print_output "[+] Identified ELF file - performing binary tests on this ELF file"
    if ! [[ -f "${LOG_DIR}"/firmware/firmware ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.elf" || print_error "[-] Binary file copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.elf" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Perl script text executable"* ]]; then
    print_output "[+] Identified Perl script - performing perl checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.pl" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.pl" || print_error "[-] Perl script file copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.pl" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"PHP script,"* ]]; then
    print_output "[+] Identified PHP script - performing PHP checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.php" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.php" || print_error "[-] PHP script file copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.php" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Python script,"* ]]; then
    print_output "[+] Identified Python script - performing Python checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.py" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.py" || print_error "[-] Python script file copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.py" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"shell script,"* ]]; then
    print_output "[+] Identified shell script - performing shell checks"
    export DISABLE_DEEP=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.sh" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.sh" || print_error "[-] Shell script file copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.sh" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"Android package (APK),"* ]]; then
    print_output "[+] Identified Android APK package - performing APK checks"
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.apk" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.apk" || print_error "[-] APK file copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.apk" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
      export DISABLE_DEEP=1
    fi
  fi
  if [[ "${lFILE_BIN_OUT}" == *"PE32 executable"* ]] || [[ "${lFILE_BIN_OUT}" == *"PE32+ executable"* ]] || [[ "${lFILE_BIN_OUT}" == *"MSI Installer"* ]]; then
    print_output "[+] Identified Windows executable"
    # Do not disable the deep extractor. If disabled we will not find hidden layers in exe files
    # e.g.: D-Link/dtlwe_r602b_04b0_4706_v1.0.0.1_190801_release_01.04.eu_.exe
    # export DISABLE_DEEP=1
    export WINDOWS_EXE=1
    if ! [[ -f "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.exe" ]]; then
      cp "${lCHECK_FILE}" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.exe" || print_error "[-] Windows executable copy process failed"
      write_csv_log_to_path "${P99_CSV_LOG}" "P02_firmware_bin_file_check" "${LOG_DIR}/firmware/${lCHECK_FILE_NAME}.exe" "NA" "NA" "NA" "NA" "NA" "${lFILE_BIN_OUT}" "${MD5_CHECKSUM}"
    fi
  fi
  # probably we need to take a deeper look to identify the gpg compressed firmware files better.
  # Currently this detection mechanism works quite good on the known firmware images
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ a3\ 01\  ]]; then
    lGPG_CHECK="$(gpg --list-packets "${FIRMWARE_PATH}" | grep "compressed packet:" || true)"
    if [[ "${lGPG_CHECK}" == *"compressed packet: algo="* ]]; then
      print_output "[+] Identified GPG compressed firmware - using GPG extraction module"
      export GPG_COMPRESS=1
      lUEFI_CHECK=0
      write_csv_log "GPG compressed firmware" "yes" "NA"
    fi
  fi
  if [[ "${lHEX_FIRST_LINE}" == *"CrAU"* ]]; then
    print_output "[+] Identified Android OTA payload.bin update file - using Android extraction module"
    export ANDROID_OTA=1
    lUEFI_CHECK=0
    write_csv_log "Android OTA update" "yes" "NA"
  fi
  if [[ "${lFILE_BIN_OUT}" == *"openssl enc'd data with salted password"* ]]; then
    print_output "[+] Identified OpenSSL encrypted file - trying OpenSSL module for Foscam firmware"
    export OPENSSL_ENC_DETECTED=1
    lUEFI_CHECK=0
    write_csv_log "OpenSSL encrypted" "yes" "NA"
  fi
  # This check is currently only tested on one firmware - further tests needed:
  if [[ "${lHEX_FIRST_LINE}" =~ 00000000\ \ 62\ 67\ 6e\ 00\ 00\ 00\ 00\ 00\ \ 00\ 00\ 00\  ]]; then
    print_output "[+] Identified Buffalo encrpyted firmware - using Buffalo extraction module"
    export BUFFALO_ENC_DETECTED=1
    write_csv_log "Buffalo encrypted" "yes" "NA"
  fi
  if [[ "${lCHECK_FILE_NAME}" =~ .*\.ri ]] && [[ "${lFILE_BIN_OUT}" == *"data"* ]]; then
    # ri files are usually used by zyxel
    if [[ -n $(find "${LOG_DIR}"/firmware -name "$(basename -s .ri "${lCHECK_FILE}")".bin -print -quit) ]]; then
      # if we find a bin file with the same name then it is a Zyxel firmware image
      print_output "[+] Identified ZyXel encrpyted ZIP firmware - using ZyXel extraction module"
      export ZYXEL_ZIP=1
      lUEFI_CHECK=0
      write_csv_log "ZyXel encrypted ZIP" "yes" ""
    fi
  fi
  if [[ "${lUEFI_CHECK}" -gt 0 ]]; then
    print_output "[+] Identified possible UEFI/BIOS firmware - using UEFI extraction module"
    UEFI_DETECTED=1
    UEFI_AMI_CAPSULE=$(grep -c "AMI.*EFI.*capsule" "${LOG_PATH_MODULE}"/p02_binwalk_output.txt || true)
    if [[ "${UEFI_AMI_CAPSULE}" -gt 0 ]]; then
      print_output "[+] Identified possible UEFI-AMI capsule firmware - using capsule extractors"
    fi
    write_csv_log "UEFI firmware detected" "yes" "NA"
  fi

  print_ln
}

# backup_p02_vars - P02变量备份函数
# 功能: 将P02模块中设置的检测标志保存到备份文件
# 参数: 无
# 返回: 创建变量备份供后续模块使用
#
# 备份的变量:
#   - FIRMWARE_PATH, UEFI_DETECTED, AVM_DETECTED, VMDK_DETECTED
#   - UBI_IMAGE, DLINK_ENC_DETECTED, ENGENIUS_ENC_DETECTED
#   - UBOOT_IMAGE, BSD_UFS, EXT_IMAGE, QNAP_ENC_DETECTED
#   - GPG_COMPRESS, ANDROID_OTA, OPENSSL_ENC_DETECTED
#   - BUFFALO_ENC_DETECTED, ZYXEL_ZIP, QCOW_DETECTED
backup_p02_vars() {
  backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
  backup_var "UEFI_DETECTED" "${UEFI_DETECTED}"
  backup_var "AVM_DETECTED" "${AVM_DETECTED}"
  backup_var "VMDK_DETECTED" "${VMDK_DETECTED}"
  backup_var "UBI_IMAGE" "${UBI_IMAGE}"
  backup_var "DLINK_ENC_DETECTED" "${DLINK_ENC_DETECTED}"
  backup_var "ENGENIUS_ENC_DETECTED" "${ENGENIUS_ENC_DETECTED}"
  backup_var "UBOOT_IMAGE" "${UBOOT_IMAGE}"
  backup_var "BSD_UFS" "${BSD_UFS}"
  backup_var "EXT_IMAGE" "${EXT_IMAGE}"
  backup_var "QNAP_ENC_DETECTED" "${QNAP_ENC_DETECTED}"
  backup_var "GPG_COMPRESS" "${GPG_COMPRESS}"
  backup_var "ANDROID_OTA" "${ANDROID_OTA}"
  backup_var "OPENSSL_ENC_DETECTED" "${OPENSSL_ENC_DETECTED}"
  backup_var "BUFFALO_ENC_DETECTED" "${BUFFALO_ENC_DETECTED}"
  backup_var "ZYXEL_ZIP" "${ZYXEL_ZIP}"
  backup_var "QCOW_DETECTED" "${QCOW_DETECTED}"
}
