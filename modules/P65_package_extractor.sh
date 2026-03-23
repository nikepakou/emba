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

# Description: 识别和提取常见软件包归档文件
# 依赖工具: dpkg-deb, rpm2cpio, cpio, unzip, tar
#             - dpkg-deb: Debian/Ubuntu软件包提取工具
#             - rpm2cpio + cpio: RPM软件包提取工具
#             - unzip: APK(Android)软件包提取工具
#             - tar: IPK(OpenWrt)软件包提取工具
#
# 环境变量:
#   - DISABLE_DEEP: 禁用深度提取标志
#   - FILES_PRE_PACKAGE: 提取前的文件数
#   - ROOT_PATH: 检测到的根路径数组
#   - FIRMWARE_PATH_CP: 固件副本路径
#   - THREADED: 多线程模式标志
#
# 支持的软件包格式:
#   - .deb / .udeb: Debian/Ubuntu DEB包
#   - .rpm: RedHat/CentOS RPM包
#   - .apk: Android APK安装包
#   - .ipk: OpenWrt IPK包
#
# 模块定位:
#   - 在深度提取后运行
#   - 提取固件中嵌入的软件包
#   - 将软件包内容提取到相应的根目录
#   - 使后续分析能访问包内的文件

# 预检线程模式 - 如果设置为1,这些模块将以线程模式运行
# 此模块用于提取固件,会阻塞需要在其后执行的模块
export PRE_THREAD_ENA=0

# P65_package_extractor - 软件包提取主函数
# 功能: 识别并提取固件中的各类软件包
# 参数: 无 (使用全局环境变量)
# 返回: 提取结果日志
#
# 提取流程:
#   1. 检查是否禁用深度提取
#   2. 统计提取前的文件数量
#   3. 依次执行各类软件包提取:
#      - deb_extractor: 提取DEB包
#      - ipk_extractor: 提取IPK包
#      - apk_extractor: 提取APK包
#      - rpm_extractor: 提取RPM包
#   4. 统计提取后的文件数量
#   5. 如果有新文件,更新架构分析和路径统计
#
# 提取条件:
#   - 磁盘空间不足时跳过对应包类型
#   - 使用-xdev只处理当前文件系统,不跨越挂载点
P65_package_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Package extractor module"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lDISK_SPACE_CRIT=0
  local lNEG_LOG=0
  export FILES_PRE_PACKAGE=0
  local lFILES_POST_PACKAGE_ARR=()
  export WAIT_PIDS_P20=()

  FILES_PRE_PACKAGE=$(find "${FIRMWARE_PATH_CP}" -type f ! -name "*.raw" | wc -l)
  if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
    deb_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no deb extraction performed" "main"
    lDISK_SPACE_CRIT=1
  fi
  if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
    ipk_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no ipk extraction performed" "main"
    lDISK_SPACE_CRIT=1
  fi
  if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
    apk_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no apk extraction performed" "main"
    lDISK_SPACE_CRIT=1
  fi
  if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
    rpm_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no rpm extraction performed" "main"
    lDISK_SPACE_CRIT=1
  fi

  mapfile -t lFILES_POST_PACKAGE_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f ! -name "*.raw")

  if [[ "${#lFILES_POST_PACKAGE_ARR[@]}" -gt "${FILES_PRE_PACKAGE}" ]]; then
    sub_module_title "Firmware package extraction details"
    print_ln
    print_output "[*] Found ${ORANGE}${#lFILES_POST_PACKAGE_ARR[@]}${NC} files."

    print_output "[*] Adjusting the backend from ${ORANGE}${FILES_PRE_PACKAGE}${NC} to ${ORANGE}${#lFILES_POST_PACKAGE_ARR[@]}${NC} entries ... take a break" "no_log"

    for lBINARY in "${lFILES_POST_PACKAGE_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done

    local lLINUX_PATH_COUNTER_PCK=0
    lLINUX_PATH_COUNTER_PCK=$(linux_basic_identification "${FIRMWARE_PATH_CP}")

    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_PCK}${NC}."
    print_ln
    tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"
    print_output "[*] Before package extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after package extraction we have now ${ORANGE}${#lFILES_POST_PACKAGE_ARR[@]}${NC} files extracted."
    lNEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

# rpm_extractor - RPM软件包提取函数
# 功能: 查找并提取固件中的RPM包
# 参数: 无 (使用全局变量)
# 返回: RPM包内容提取到根目录
#
# 依赖工具: rpm2cpio, cpio
#   - rpm2cpio: 将RPM转换为cpio格式
#   - cpio: 从cpio归档中提取文件
#
# 处理逻辑:
#   1. 查找所有.rpm文件(去重)
#   2. 对每个根路径下的每个RPM包进行提取
#   3. 使用rpm2cpio | cpio管道提取到目标目录
#   4. 统计提取后的文件数量
rpm_extractor() {
  sub_module_title "RPM archive extraction mode"

  local lRPM_ARCHIVES_ARR=()
  local lRPM_NAME=""
  local lFILES_AFTER_RPM=0
  local lR_PATH=""
  local lRPM=""

  print_output "[*] Identify RPM archives and extracting it to the root directories ..."
  mapfile -t lRPM_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.rpm" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lRPM_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Identified ${ORANGE}${#lRPM_ARCHIVES_ARR[@]}${NC} RPM archives - extracting archives to the root directories ..."
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lRPM in "${lRPM_ARCHIVES_ARR[@]}"; do
        lRPM_NAME=$(basename "${lRPM}")
        print_output "[*] Extracting ${ORANGE}${lRPM_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
        rpm2cpio "${lRPM}" | cpio -D "${lR_PATH}" -idm || true
      done
    done

    lFILES_AFTER_RPM=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before deep extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after RPM extraction we have ${ORANGE}${lFILES_AFTER_RPM}${NC} files extracted."
  else
    print_output "[-] No rpm packages extracted."
  fi
}

# apk_extractor - Android APK软件包提取函数
# 功能: 查找并提取固件中的APK包
# 参数: 无 (使用全局变量)
# 返回: APK包内容提取到根目录
#
# 依赖工具: unzip
#   - APK本质是zip压缩包,使用unzip提取
#
# 处理逻辑:
#   1. 查找所有.apk文件(去重)
#   2. 对每个根路径下的每个APK包进行提取
#   3. 使用unzip -o强制覆盖提取到目标目录
#   4. 统计提取后的文件数量
apk_extractor() {
  sub_module_title "Android APK archive extraction mode"

  local lAPK_ARCHIVES_ARR=()
  local lAPK_NAME=""
  local lFILES_AFTER_APK=0
  local lR_PATH=""
  local lAPK=""

  print_output "[*] Identify apk archives and extracting it to the root directories ..."
  mapfile -t lAPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.apk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lAPK_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${#lAPK_ARCHIVES_ARR[@]}${NC} APK archives - extracting them to the root directories ..."
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lAPK in "${lAPK_ARCHIVES_ARR[@]}"; do
        lAPK_NAME=$(basename "${lAPK}")
        print_output "[*] Extracting ${ORANGE}${lAPK_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
        unzip -o -d "${lR_PATH}" "${lAPK}" || true
      done
    done

    lFILES_AFTER_APK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before apk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_APK}${NC} files extracted."
  else
    print_output "[-] No apk packages extracted."
  fi
}

# ipk_extractor - OpenWrt IPK软件包提取函数
# 功能: 查找并提取固件中的IPK包
# 参数: 无 (使用全局变量)
# 返回: IPK包内容提取到根目录
#
# 依赖工具: tar
#   - IPK包本质是tar.gz(有时是纯gzip)压缩包
#   - 结构: control.tar.gz + data.tar.gz 打包在 tar.gz 中
#
# 处理逻辑:
#   1. 查找所有.ipk文件(去重)
#   2. 检测是否为gzip格式(有些IPK直接是gzip)
#   3. 提取tar包中的data.tar.gz
#   4. 从data.tar.gz中提取实际文件到目标目录
#   5. 清理临时目录
#   6. 统计提取后的文件数量
ipk_extractor() {
  sub_module_title "IPK archive extraction mode"
  local lIPK_ARCHIVES_ARR=()
  local lIPK_NAME=""
  local lFILES_AFTER_IPK=0
  local lR_PATH=""
  local lIPK=""

  print_output "[*] Identify ipk archives and extracting it to the root directories ..."
  mapfile -t lIPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.ipk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lIPK_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${#lIPK_ARCHIVES_ARR[@]}${NC} IPK archives - extracting them to the root directories ..."
    mkdir "${LOG_DIR}"/ipk_tmp
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lIPK in "${lIPK_ARCHIVES_ARR[@]}"; do
        lIPK_NAME=$(basename "${lIPK}")
        if [[ $(file -b "${lIPK}") == *"gzip"* ]]; then
          print_output "[*] Extracting ${ORANGE}${lIPK_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
          tar zxpf "${lIPK}" --directory "${LOG_DIR}"/ipk_tmp || true
        else
          print_output "[-] Is ${ORANGE}${lIPK_NAME}${NC} a valid ipk (tgz) archive?"
        fi
        if [[ -f "${LOG_DIR}"/ipk_tmp/data.tar.gz ]]; then
          tar xzf "${LOG_DIR}"/ipk_tmp/data.tar.gz --directory "${lR_PATH}" || true
        fi
        if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
          rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
        fi
      done
    done

    lFILES_AFTER_IPK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f ! -name "*.raw" | wc -l )
    print_ln "no_log"
    print_output "[*] Before ipk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_IPK}${NC} files extracted."
    if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
      rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
    fi
  else
    print_output "[-] No ipk packages extracted."
  fi
}

# deb_extractor - Debian DEB软件包提取函数
# 功能: 查找并提取固件中的DEB包
# 参数: 无 (使用全局变量)
# 返回: DEB包内容提取到根目录
#
# 依赖工具: dpkg-deb
#   - Debian软件包管理工具
#   - 支持--extract参数直接提取内容
#
# 处理逻辑:
#   1. 查找所有.deb和.udeb文件(去重)
#   2. 对每个根路径下的每个DEB包进行提取
#   3. 支持多线程模式(THREADED=1)
#   4. 使用dpkg-deb --extract提取到目标目录
#   5. 统计提取后的文件数量
deb_extractor() {
  sub_module_title "Debian archive extraction mode"

  local lDEB_ARCHIVES_ARR=()
  local lFILES_AFTER_DEB=0
  local lR_PATH=""
  local lDEB=""

  print_output "[*] Identify debian archives and extracting it to the root directories ..."
  mapfile -t lDEB_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f \( -name "*.deb" -o -name "*.udeb" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lDEB_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${#lDEB_ARCHIVES_ARR[@]}${NC} debian archives - extracting them to the root directories ..."
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lDEB in "${lDEB_ARCHIVES_ARR[@]}"; do
        print_output "[*] Extracting ${lDEB} to ${lR_PATH}"
        if [[ "${THREADED}" -eq 1 ]]; then
          extract_deb_extractor_helper "${lDEB}" "${lR_PATH}" &
          WAIT_PIDS_P20+=( "$!" )
        else
          extract_deb_extractor_helper "${lDEB}" "${lR_PATH}"
        fi
      done
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_P20[@]}"

    lFILES_AFTER_DEB=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before deb extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_DEB}${NC} files extracted."
  else
    print_output "[-] No deb packages extracted."
  fi
}

# extract_deb_extractor_helper - DEB包提取辅助函数
# 功能: 单个DEB包的提取操作
# 参数:
#   $1 - lDEB: DEB包文件路径
#   $2 - lR_PATH: 目标提取目录
# 返回: 提取的文件保存到目标目录
#
# 工具: dpkg-deb --extract
#   - 提取DEB包内容到指定目录
#   - 不安装包,只提取文件
extract_deb_extractor_helper() {
  local lDEB="${1:-}"
  local lR_PATH="${2:-}"
  local lDEB_NAME=""

  lDEB_NAME=$(basename "${lDEB}")
  print_output "[*] Extracting ${ORANGE}${lDEB_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
  dpkg-deb --extract "${lDEB}" "${lR_PATH}" || true
}

