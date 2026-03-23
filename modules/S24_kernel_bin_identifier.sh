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

# ==========================================================================================
# 模块名称: S24_kernel_bin_identifier (内核二进制文件标识符)
#
# 功能描述:
#   本模块用于从固件镜像中识别Linux内核文件，并提取相关的配置信息。主要功能包括:
#   1. 识别内核二进制文件 - 通过字符串特征匹配识别可能是Linux内核的文件
#   2. 提取内核配置 - 从内核镜像中提取嵌入式配置文件(.config)
#   3. 转换内核格式 - 使用vmlinux-to-elf工具将压缩/原始内核转换为ELF格式
#   4. 识别init命令行 - 从内核字符串中查找启动参数中的init路径
#   5. 安全配置检查 - 使用kconfig-hardened-checker检查内核安全加固设置
#
# 依赖工具:
#   - vmlinux-to-elf: 将原始/压缩内核转换为ELF格式
#   - kconfig-hardened-checker: 检查内核安全配置
#   - strings: 提取文件字符串
#   - readelf: 分析ELF文件结构
#
# 输入:
#   - P99_CSV_LOG: 预处理器生成的二进制文件列表(来自s09模块)
#   - CONFIG_DIR/bin_version_identifiers/linux_kernel.json: 内核版本识别规则
#
# 输出:
#   - S24_CSV_LOG: 包含识别结果的内核信息CSV日志
#   - 内核配置文件提取结果
#   - 内核安全检查报告
# ==========================================================================================

# 设置线程优先级为1(低优先级),避免影响其他关键分析任务
export THREAD_PRIO=1

# ==========================================================================================
# S24_kernel_bin_identifier - 内核二进制文件识别主函数
#
# 工作流程:
#   1. 初始化模块日志和标题
#   2. 准备CSV日志输出格式
#   3. 确保字符串输出目录存在
#   4. 并行处理每个二进制文件(通过binary_kernel_check_threader函数)
#   5. 收集并合并所有线程的输出日志
#   6. 统计识别结果数量
# ==========================================================================================
S24_kernel_bin_identifier()
{
  # 初始化模块日志系统
  module_log_init "${FUNCNAME[0]}"
  # 显示模块标题
  module_title "Kernel Binary and Configuration Identifier"
  # 预报告模块状态
  pre_module_reporter "${FUNCNAME[0]}"

  # 局部变量声明
  local lNEG_LOG=0                  # 负日志计数(未识别数量)
  local lFILE_PATH=""                # 文件路径
  local lK_INITS_ARR=()             # 内核init参数数组
  local lK_INIT=""                   # 单个init参数
  local lCFG_MD5=""                  # 配置文件MD5值
  export KCFG_MD5_ARR=()             # 导出: 内核配置MD5数组(用于去重)

  # 写入CSV日志表头 - 记录内核分析结果的各个字段
  # 字段说明:
  #   file path: 内核文件路径
  #   Kernel version stripped: 提取的内核版本号
  #   file output: 输出文件类型(ELF/原始内核等)
  #   identified init: 识别到的init命令行参数
  #   config extracted: 是否成功提取内核配置
  #   kernel symbols: 内核符号数量
  #   architecture: 处理器架构
  #   endianness: 字节序(大端/小端)
  write_csv_log "file path" "Kernel version stripped" "file output" "identified init" "config extracted" "kernel symbols" "architecture" "endianness"

  # 存储后台进程的PID数组
  local lWAIT_PIDS_S24_main=()

  # 确保s09模块的字符串输出目录存在(用于存储提取的字符串)
  # 如果s09模块尚未运行,手动创建该目录
  if ! [[ -d "${S09_LOG_DIR}"/strings_bins/ ]]; then
    mkdir -p "${S09_LOG_DIR}"/strings_bins/ 2>/dev/null
  fi

  # 从P99_CSV_LOG读取二进制文件列表并进行过滤和处理
  # 过滤掉ASCII text和Unicode text类型的文件(这些不是二进制文件)
  # 使用sort -u去重,然后并行处理每个文件
  while read -r lBINARY_ENTRY; do
    # 启动后台线程处理每个二进制文件
    binary_kernel_check_threader "${lBINARY_ENTRY}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S24_main+=( "${lTMP_PID}" )
    # 限制最大并发线程数,避免资源耗尽
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S24_main
  done < <(grep -v "ASCII text\|Unicode text" "${P99_CSV_LOG}" | sort -u || true)

  # 等待所有后台进程完成
  wait_for_pid "${lWAIT_PIDS_S24_main[@]}"
  # shellcheck disable=SC2153

  # 合并所有线程的临时日志文件到主日志
  find "${LOG_PATH_MODULE}" -name "threading_*.tmp" -exec cat {} \; | tee -a "${LOG_FILE}"

  # 检查S24_CSV_LOG文件是否存在及是否包含有效数据
  if [[ -f "${S24_CSV_LOG}" ]]; then
    # 如果有多行数据(表头+至少一行数据)
    if [[ $(wc -l < "${S24_CSV_LOG}") -gt 1 ]]; then
      lNEG_LOG=$(wc -l < "${S24_CSV_LOG}" 2>/dev/null || echo 0)
    else
      # 如果只有表头,删除该文件
      rm "${S24_CSV_LOG}"
    fi
  fi

  # 记录模块结束日志
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

# ==========================================================================================
# binary_kernel_check_threader - 二进制内核文件检查线程函数
#
# 功能: 对单个二进制文件进行内核识别分析
#
# 处理流程:
#   1. 解析二进制文件条目信息
#   2. 过滤非目标文件类型(文本/归档等)
#   3. 提取文件字符串
#   4. 根据JSON规则匹配内核版本标识
#   5. 检测init命令行参数
#   6. 尝试转换为ELF格式
#   7. 提取内核配置
#   8. 执行安全配置检查
#   9. 记录分析结果到CSV
#
# 参数:
#   $1 - lBINARY_ENTRY: 二进制文件条目(CSV格式)
# ==========================================================================================
binary_kernel_check_threader() {
  # 从参数获取二进制文件条目(CSV格式)
  local lBINARY_ENTRY="${1:-}"

  # 局部变量声明
  local lFILE_PATH=""              # 文件完整路径
  local lFILE_NAME=""              # 文件名

  # 从CSV条目中提取文件路径(第2个字段)
  lFILE_PATH=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f2)
  # 提取文件名
  lFILE_NAME=$(basename "${lFILE_PATH}")

  # 创建线程日志文件
  local lLOG_FILE="${LOG_PATH_MODULE}/threading_${lFILE_NAME}.tmp"

  # 初始化各分析结果变量
  local lBIN_FILE="NA"             # 文件类型
  local lKCONFIG_EXTRACTED="NA"   # 提取的内核配置路径
  local lK_VER_CLEAN="NA"          # 清理后的内核版本
  local lK_INIT="NA"               # init命令行参数
  local lK_SYMBOLS=0              # 内核符号数量
  local lK_ARCH="NA"               # 处理器架构
  local lK_ARCH_END="NA"           # 字节序(EL=小端, EB=大端)
  local lK_CON_DET=""              # 内核配置检测结果
  local lK_FILE=""                  # 内核文件类型
  local lK_VER_TMP=""              # 临时内核版本

  # 导出包类型信息(用于版本记录)
  export PACKAGING_SYSTEM="linux_kernel"
  export TYPE="operating-system"

  # 从CSV提取文件类型(第8个字段)
  lBIN_FILE=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f8)

  # 过滤掉不需要分析的文件类型:
  # - empty: 空文件
  # - text: 文本文件
  # - archive: 归档文件
  # - compressed: 压缩文件
  # - image data: 镜像数据
  if [[ "${lBIN_FILE}" == "empty" || "${lBIN_FILE}" == *"text"* || "${lBIN_FILE}" == *" archive "* || "${lBIN_FILE}" == *" compressed "* || "${lBIN_FILE}" == *" image data"* ]]; then
    return
  fi

  # 提取文件MD5校验和(第9个字段),用于字符串缓存文件命名
  lMD5_SUM=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f9)
  lBIN_NAME_REAL="$(basename "${lFILE_PATH}")"

  # 字符串输出文件路径: ${S09_LOG_DIR}/strings_bins/strings_${MD5}_${文件名}.txt
  # 优先使用s09模块已生成的字符串文件,如果不存在则重新生成
  lSTRINGS_OUTPUT="${S09_LOG_DIR}"/strings_bins/strings_"${lMD5_SUM}"_"${lBIN_NAME_REAL}".txt

  # 确保输出目录存在
  if ! [[ -d "${S09_LOG_DIR}/strings_bins" ]]; then
    mkdir -p "${S09_LOG_DIR}/strings_bins"
  fi

  # 如果字符串文件不存在,使用strings命令提取文件中的可打印字符串
  if ! [[ -f "${lSTRINGS_OUTPUT}" ]]; then
    strings "${lFILE_PATH}" | uniq > "${lSTRINGS_OUTPUT}" || true
  fi

  # 内核版本识别配置文件路径
  lVERSION_JSON_CFG="${CONFIG_DIR}/bin_version_identifiers/linux_kernel.json"

  # 声明用于存储JSON配置数据的数组
  local lPARSING_MODE_ARR=()
  local lRULE_IDENTIFIER=""        # 规则标识符
  local lLICENSES_ARR=()          # 许可证数组
  local lPRODUCT_NAME_ARR=()      # 产品名称数组
  local lVENDOR_NAME_ARR=()       # 供应商名称数组
  local lCSV_REGEX_ARR=()         # CSV正则提取规则
  local lVERSION_IDENTIFIER_ARR=() # 版本标识符(grep命令模式)

  # shellcheck disable=SC2034
  # 使用jq从JSON配置中解析各种字段
  mapfile -t lPARSING_MODE_ARR < <(jq -r .parsing_mode[] "${lVERSION_JSON_CFG}")
  lRULE_IDENTIFIER=$(jq -r .identifier "${lVERSION_JSON_CFG}" || print_error "[-] Error in parsing ${lVERSION_JSON_CFG}")
  # shellcheck disable=SC2034
  mapfile -t lLICENSES_ARR < <(jq -r .licenses[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lPRODUCT_NAME_ARR < <(jq -r .product_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lVENDOR_NAME_ARR < <(jq -r .vendor_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lCSV_REGEX_ARR < <(jq -r .version_extraction[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # 从JSON中获取grep命令模式,用于匹配内核版本字符串
  mapfile -t lVERSION_IDENTIFIER_ARR < <(jq -r .grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)

  # 遍历所有版本标识符模式进行匹配
  for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
    # 使用grep从字符串文件中查找匹配的模式
    # -a: 视为二进制文件
    # -o: 只输出匹配部分
    # -E: 扩展正则表达式
    mapfile -t lVERSION_IDENTIFIED_ARR < <(grep -a -o -E "${lVERSION_IDENTIFIER}" "${lSTRINGS_OUTPUT}"| sort -u || true)

    # 如果找到匹配的内核版本标识
    if [[ "${#lVERSION_IDENTIFIED_ARR[@]}" -gt 0 ]]; then
      write_log "" "${lLOG_FILE}"
      # 记录所有匹配到的内核版本
      for lVERSION_IDENTIFIED in "${lVERSION_IDENTIFIED_ARR[@]}"; do
        write_log "[+] Possible Linux Kernel found: ${ORANGE}${lFILE_PATH} / ${lVERSION_IDENTIFIED}${NC}" "${lLOG_FILE}"
      done
      write_log "" "${lLOG_FILE}"

      # ============================================================
      # 步骤1: 检测内核命令行中的init参数
      # 支持两种格式:
      #   - init=/path/to/init: 标准的init参数
      #   - rdinit=/path/to/init: initramfs的init参数
      # ============================================================
      # rough init entry detection
      # grep查找init=开头的行,然后通过sed和awk提取路径
      mapfile -t lK_INITS_ARR < <(grep -E "init=\/" "${lSTRINGS_OUTPUT}" | sed 's/.*rdinit/rdinit/' | sed 's/.*\ init/init/' | awk '{print $1}' | tr -d '"' | sort -u || true)
      for lK_INIT in "${lK_INITS_ARR[@]}"; do
        # 验证格式是否为 init=/xxx (以/开头的路径)
        if [[ "${lK_INIT}" =~ init=\/.* ]]; then
          write_log "[+] Init found in Linux kernel file ${ORANGE}${lFILE_PATH}${NC}" "${lLOG_FILE}"
          write_log "" "${lLOG_FILE}"
          write_log "$(indent "$(orange "${lK_INIT}")")" "${lLOG_FILE}"
          write_log "" "${lLOG_FILE}"
        else
          # 无效格式,设为NA
          lK_INIT="NA"
        fi
      done

      # ============================================================
      # 步骤2: 尝试将内核文件转换为ELF格式
      # 使用vmlinux-to-elf工具:
      #   - 如果是原始内核镜像,转换为ELF
      #   - 如果已是ELF文件,可以提取更多信息
      # ============================================================
      # we test all possible kernel files with vmlinux-to-elf. It does not matter if it is already an elf file or not
      # if it is already an elf file we need the output for the module report
      if [[ -e "${EXT_DIR}"/vmlinux-to-elf/vmlinux-to-elf ]]; then
        write_log "[*] Testing possible Linux kernel file ${ORANGE}${lFILE_PATH}${NC} with ${ORANGE}vmlinux-to-elf:${NC}" "${lLOG_FILE}"
        write_log "" "${lLOG_FILE}"
        # 执行vmlinux-to-elf转换
        # 输入: lFILE_PATH (原始/压缩内核)
        # 输出: lFILE_PATH.elf (转换后的ELF文件)
        "${EXT_DIR}"/vmlinux-to-elf/vmlinux-to-elf "${lFILE_PATH}" "${lFILE_PATH}".elf 2>/dev/null >> "${lLOG_FILE}" || true

        # 如果成功生成ELF文件
        if [[ -f "${lFILE_PATH}".elf ]]; then
          # 计算ELF文件的MD5
          lMD5_SUM=$(md5sum "${lFILE_PATH}".elf)
          lMD5_SUM="${lMD5_SUM/\ *}"

          # 检查ELF文件是否已在P99 CSV中存在
          if ! grep -q "${lMD5_SUM}" "${P99_CSV_LOG}"; then
            # 如果不存在,需要将新ELF文件添加到P99 CSV
            # 调用binary_architecture_threader分析ELF文件的架构
            binary_architecture_threader "${lFILE_PATH}.elf" "${FUNCNAME[0]}"
            # 从P99 CSV中获取该ELF文件的条目
            lBINARY_ENTRY="$(grep -F "${lFILE_PATH}.elf" "${P99_CSV_LOG}" | sort -u | head -1 || true)"
          else
            # 如果已存在,从P99 CSV中提取该条目
            lBINARY_ENTRY="$(grep "${lMD5_SUM}" "${P99_CSV_LOG}" | sort -u | head -1 || true)"
          fi
          # 重新提取文件类型字段
          lBIN_FILE=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f8)

          # 如果成功转换为ELF类型
          if [[ "${lBIN_FILE}" == *"ELF"* ]]; then
            write_log "" "${lLOG_FILE}"
            write_log "[+] Successfully generated Linux kernel elf file: ${ORANGE}${lFILE_PATH}.elf${NC}" "${lLOG_FILE}"
            # 设置高置信度级别(4级)
            export CONFIDENCE_LEVEL=4

            # 记录版本解析日志
            for lVERSION_IDENTIFIED in "${lVERSION_IDENTIFIED_ARR[@]}"; do
              version_parsing_logging "${S09_CSV_LOG}" "S24_kernel_bin_identifier" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"
            done
            # 后续使用ELF文件进行分析
            lFILE_PATH+=".elf"
          else
            write_log "" "${lLOG_FILE}"
            write_log "[-] No Linux kernel elf file was created." "${lLOG_FILE}"
          fi
        fi
        write_log "" "${lLOG_FILE}"
      fi

      # ============================================================
      # 步骤3: 如果没有成功生成ELF文件,则记录原始内核
      # ============================================================
      # if we have no elf file created and logged we now log the original kernel
      # in case we have an elf file lFILE_PATH was already included in the SBOM
      if [[ ! -f "${lFILE_PATH}.elf" ]] && [[ "${lBIN_FILE}" != *"ELF"* ]]; then
        for lVERSION_IDENTIFIED in "${lVERSION_IDENTIFIED_ARR[@]}"; do
          if version_parsing_logging "${S09_CSV_LOG}" "S24_kernel_bin_identifier" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
            # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} for non ELF kernel -> continue to next binary"
            return
          fi
        done
      fi

      # ============================================================
      # 步骤4: 非SBOM_MINIMAL模式下进行深度分析
      # - 提取内核配置
      # - 分析架构和字节序
      # - 执行安全配置检查
      # ============================================================
      # ensure this is only done in non SBOM_MINIMAL mode
      if [[ "${SBOM_MINIMAL:-0}" -eq 0 ]] ; then
        # 从ELF文件条目中获取文件类型信息
        lK_FILE=$(echo "${lBINARY_ENTRY}" | cut -d ';' -f8)

        # 如果是ELF文件,提取更详细的架构信息
        if [[ "${lK_FILE}" == *"ELF"* ]]; then
          # 使用readelf统计函数和对象符号数量
          lK_SYMBOLS="$(readelf -W -s "${lFILE_PATH}" | grep -c "FUNC\|OBJECT" || true)"

          # 检测字节序:
          # LSB = Little Endian (小端) -> EL
          # MSB = Big Endian (大端) -> EB
          [[ "${lK_FILE}" == *"LSB"* ]] && lK_ARCH_END="EL"
          [[ "${lK_FILE}" == *"MSB"* ]] && lK_ARCH_END="EB"

          # 检测处理器架构:
          [[ "${lK_FILE}" == *"MIPS"* ]] && lK_ARCH="MIPS"
          [[ "${lK_FILE}" == *"ARM"* ]] && lK_ARCH="ARM"
          [[ "${lK_FILE}" == *"80386"* ]] && lK_ARCH="x86"
          [[ "${lK_FILE}" == *"x86-64"* ]] && lK_ARCH="x64"
          [[ "${lK_FILE}" == *"PowerPC"* ]] && lK_ARCH="PPC"
          [[ "${lK_FILE}" == *"UCB RISC-V"* ]] && lK_ARCH="RISCV"
          [[ "${lK_FILE}" == *"QUALCOMM DSP6"* ]] && lK_ARCH="QCOM_DSP6"
        else
          # 回退方案: 从主日志中猜测架构
          # fallback
          lK_ARCH=$(grep "Guessed architecture" "${LOG_FILE}" | cut -d: -f2 | awk '{print $1}' | sort -u || true)
          # 从架构名称后缀判断字节序(le=小端, be=大端)
          [[ "${lK_ARCH: -2}" == "le" ]] && lK_ARCH_END="EL"
          [[ "${lK_ARCH: -2}" == "be" ]] && lK_ARCH_END="EB"
        fi

        # ============================================================
        # 步骤5: 提取内核配置文件(.config)
        # 需要先禁用strict mode再执行提取
        # ============================================================
        disable_strict_mode "${STRICT_MODE}" 0
        extract_kconfig "${lFILE_PATH}" "${lLOG_FILE}"
        lKCONFIG_EXTRACTED="${KCONFIG_EXTRACTED}"
        enable_strict_mode "${STRICT_MODE}" 0

        # 统计提取到的配置项数量
        local lCFG_CNT=0
        if [[ -f "${lKCONFIG_EXTRACTED}" ]]; then
          lCFG_CNT=$(grep -c CONFIG_ "${lKCONFIG_EXTRACTED}")
        fi

        # double check we really have a Kernel config extracted
        # 验证条件: 文件存在且包含超过50个CONFIG_项
        if [[ -f "${lKCONFIG_EXTRACTED}" ]] && [[ "${lCFG_CNT}" -gt 50 ]]; then
          write_log "[+] Extracted kernel configuration (${ORANGE}${lCFG_CNT} configuration entries${GREEN}) from ${ORANGE}$(basename "${lFILE_PATH}")${NC}" "${lLOG_FILE}"
          write_link "${lKCONFIG_EXTRACTED}" "${lLOG_FILE}"
          # 执行内核安全配置检查
          check_kconfig "${lKCONFIG_EXTRACTED}" "${lK_ARCH}" "${lLOG_FILE}"
        else
          write_log "[-] No valid kernel configuration extracted from ${ORANGE}$(basename "${lFILE_PATH}")${NC}" "${lLOG_FILE}"
          write_link "${lKCONFIG_EXTRACTED}" "${lLOG_FILE}"
        fi

        # ============================================================
        # 步骤6: 记录最终分析结果到CSV
        # ============================================================
        for lVERSION_IDENTIFIED in "${lVERSION_IDENTIFIED_ARR[@]}"; do
          # print_output "[*] Check for ELF - ${lBINARY_ENTRY}"

          # 清理版本字符串,移除"Linux version "前缀
          lK_VER_TMP="${lVERSION_IDENTIFIED/Linux version /}"
          # 对版本进行清理和标准化
          demess_kv_version "${lK_VER_TMP}"
          # -> KV_ARR
          # we should only get one element back, but as array

          # 遍历清理后的版本数组
          for lK_VER_CLEAN in "${KV_ARR[@]}"; do
            # 如果找到init参数
            if [[ "${#lK_INITS_ARR[@]}" -gt 0 ]]; then
              for lK_INIT in "${lK_INITS_ARR[@]}"; do
                # one dirty check if this could be a real config
                # 如果配置项少于50个,可能不是有效的内核配置
                if [[ "${lCFG_CNT}" -lt 50 ]]; then
                  lKCONFIG_EXTRACTED="NA"
                fi
                # 写入CSV日志
                write_csv_log "${lFILE_PATH}" "${lK_VER_CLEAN}" "${lBIN_FILE:-NA}" "${lK_INIT}" "${lKCONFIG_EXTRACTED}" "${lK_SYMBOLS}" "${lK_ARCH}" "${lK_ARCH_END}"
              done
            else
              # 没有找到init参数
              write_csv_log "${lFILE_PATH}" "${lK_VER_CLEAN}" "${lBIN_FILE:-NA}" "NA" "${lKCONFIG_EXTRACTED}" "${lK_SYMBOLS}" "${lK_ARCH}" "${lK_ARCH_END}"
            fi
          done
        done
      fi

    # ============================================================
    # 步骤7: 处理纯ASCII内核配置文件
    # 有些固件直接包含未编译的内核配置文件
    # ============================================================
    # ASCII kernel config files:
    elif file -b "${lFILE_PATH}" | grep -q "ASCII"; then
      # ensure this is only done in non SBOM_MINIMAL mode
      if [[ "${SBOM_MINIMAL:-0}" -eq 0 ]] ; then
        # 计算配置文件MD5用于去重
        lCFG_MD5=$(md5sum "${lFILE_PATH}" | awk '{print $1}')
        # 检查是否已分析过相同配置
        if [[ ! " ${KCFG_MD5_ARR[*]} " =~ ${lCFG_MD5} ]]; then
          # 查找内核配置文件的特征头部
          # 格式: "# Linux x.x.x Kernel Configuration"
          lK_CON_DET=$(grep -E "^# Linux.*[0-9]{1}\.[0-9]{1,2}\.[0-9]{1,2}.* Kernel Configuration" "${lSTRINGS_OUTPUT}" || true)
          if [[ "${lK_CON_DET}" =~ \ Kernel\ Configuration ]]; then
            write_log "" "${lLOG_FILE}"
            write_log "[+] Found kernel configuration file: ${ORANGE}${lFILE_PATH}${NC}" "${lLOG_FILE}"
            # 执行安全配置检查
            check_kconfig "${lFILE_PATH}" "NA" "${lLOG_FILE}"
            # 添加到已分析列表
            KCFG_MD5_ARR+=("${lCFG_MD5}")
          fi
        fi
      fi
    fi
  done
}

# ==========================================================================================
# extract_kconfig - 从内核镜像中提取嵌入式配置文件(.config)
#
# 原理说明:
#   Linux内核在编译时如果启用了CONFIG_IKCONFIG选项,会将完整的.config文件
#   以压缩形式嵌入到内核镜像中。本函数使用与Linux官方extract-ikconfig脚本
#   相同的算法来提取这个嵌入的配置。
#
# 实现步骤:
#   1. 首先尝试直接在文件查找IKCFG_ST签名(未压缩的内核)
#   2. 如果未找到,依次尝试各种压缩格式的解压:
#      - gzip, xz, bzip2, lzma, lzop, lz4, zstd
#   3. 找到配置后验证并保存到日志目录
#
# 技术细节:
#   - IKCFG_ST签名用于标记嵌入式配置的起始位置
#   - 使用tr命令处理旧版grep的字节偏移报告问题
#   - 返回值4表示成功提取,返回给调用者
#
# 参数:
#   $1 - IMG: 要分析的内核镜像文件路径
#   $2 - lLOG_FILE: 日志文件路径
#
# 依赖:
#   - dump_config(): 实际提取配置的函数
#   - try_decompress(): 尝试不同压缩格式的函数
#   - 各种解压缩工具: gunzip, unxz, bunzip2, unlzma, lzop, lz4, unzstd
# ==========================================================================================
extract_kconfig() {
  # 源码参考: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  # extract-ikconfig - Extract the .config file from a kernel image
  #
  # This will only work when the kernel was compiled with CONFIG_IKCONFIG.
  # (只有当内核编译时启用了CONFIG_IKCONFIG选项时才能工作)
  #
  # The obscure use of the "tr" filter is to work around older versions of
  # "grep" that report the byte offset of the line instead of the pattern.
  # (使用tr过滤器是为了处理旧版grep报告字节偏移而非模式的问题)
  #
  # (c) 2009,2010 Dick Streefland <dick@streefland.net>
  # Licensed under the terms of the GNU General Public License.
  # (基于GNU通用公共许可证发布)

  # Check invocation: 检查参数
  export IMG="${1:-}"              # 要分析的内核镜像文件
  local lLOG_FILE="${2:-}"           # 日志文件路径

  export KCONFIG_EXTRACTED=""       # 初始化提取结果为空

  # 检查内核文件是否存在
  if ! [[ -f "${IMG}" ]]; then
    write_log "[-] No kernel file to analyze here - ${ORANGE}${IMG}${NC}" "${lLOG_FILE}"
    return
  fi

  # 记录开始提取配置
  write_log "[*] Trying to extract kernel configuration from ${ORANGE}${IMG}${NC}" "${lLOG_FILE}"

  # 定义嵌入式配置的魔术签名
  # IKCFG_ST: 标记配置数据起始位置
  # 0123456789: 用于定位的长度标记
  export CF1='IKCFG_ST\037\213\010'
  export CF2='0123456789'

  # 准备临时文件用于解压过程
  export TMP1="${TMP_DIR}"/ikconfig$$.1   # 临时文件1
  export TMP2="${TMP_DIR}"/ikconfig$$.2   # 临时文件2
  # shellcheck disable=SC2064
  # 设置退出时清理临时文件
  trap "rm -f ${TMP1} ${TMP2}" 0

  # ============================================================
  # 第一步: 尝试在未压缩的文件中直接查找配置
  # 适用于:
  #   - 原始vmlinux文件
  #   - 包含IKCONFIG的ELF目标文件
  # ============================================================
  # Initial attempt for uncompressed images or objects:
  dump_config "${IMG}" "${lLOG_FILE}"
  # 如果返回值为4,表示成功提取,退出函数
  [[ $? -eq 4 ]] && return

  # ============================================================
  # 第二步: 尝试各种压缩格式
  # Linux内核常用的压缩格式:
  # ============================================================

  # 1. gzip格式 (最常见)
  # 签名: \037\213\010 (即 1F 8B 08)
  # That didn't work, so retry after decompression.
  try_decompress '\037\213\010' xy    gunzip "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return

  # 2. xz格式
  # 签名: \3757zXZ\000 (即 FD 37 7A 58 5A 00)
  try_decompress '\3757zXZ\000' abcde unxz "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return

  # 3. bzip2格式
  # 签名: BZh (即 42 5A 68)
  try_decompress 'BZh'          xy    bunzip2 "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return

  # 4. lzma格式
  # 签名: \135\0\0\0 (即 5D 00 00 00)
  try_decompress '\135\0\0\0'   xxx   unlzma "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return

  # 5. lzop格式
  # 签名: \211\114\132 (即 89 4C 5A)
  try_decompress '\211\114\132' xy    'lzop -d' "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return

  # 6. lz4格式
  # 签名: \002\041\114\030 (即 02 21 4C 18)
  try_decompress '\002\041\114\030' xyy 'lz4 -d -l' "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return

  # 7. zstd格式 (较新,内核5.1+支持)
  # 签名: \050\265\057\375 (即 28 B5 2F FD)
  try_decompress '\050\265\057\375' xxx unzstd "${lLOG_FILE}"
  [[ $? -eq 4 ]] && return
}

# ==========================================================================================
# dump_config - 尝试从镜像中提取内核配置的核心函数
#
# 工作原理:
#   1. 使用tr命令转换文件内容,将IKCFG_ST和数字字符转换为特定格式
#   2. 使用grep查找数字标记的开始位置(标记配置数据)
#   3. 定位到配置数据的实际位置(跳过8字节的头部)
#   4. 使用zcat解压并提取配置
#   5. 验证提取的内容是否为有效的内核配置
#
# 算法说明:
#   IKCFG_ST是嵌入配置的开始标记
#   后面跟着的8字节是长度信息
#   然后是gzip压缩的配置数据
#
# 参数:
#   $1 - lIMG_: 镜像文件路径
#   $2 - lLOG_FILE: 日志文件路径
#
# 返回值:
#   4: 成功提取到配置
#   其他: 未找到或提取失败
# ==========================================================================================
dump_config() {
  # 源码参考: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  local lIMG_="${1:-}"             # 镜像文件
  local lLOG_FILE="${2:-}"         # 日志文件
  local lCFG_MD5=""                # 配置文件的MD5

  # 检查文件是否存在
  if ! [[ -f "${lIMG_}" ]]; then
    write_log "[-] No kernel file to analyze here - ${ORANGE}${lIMG_}${NC}" "${lLOG_FILE}"
    return
  fi

  # ============================================================
  # 核心算法: 查找IKCFG_ST标记
  #
  # tr命令将:
  #   - IKCFG_ST\037\213\010 转换为换行+等号 (用于grep定位)
  #   - 数字字符0123456789 转换为 换行+等号
  #
  # 这样IKCFG_ST\n后面的第一个数字序列就是配置数据的长度标记
  # grep -abo: a=binary, o=only matching, b=byte offset
  # ============================================================
  if POS=$(tr "${CF1}\n${CF2}" "\n${CF2}=" < "${lIMG_}" | grep -abo "^${CF2}"); then
    # 提取字节偏移量(去掉grep返回的"偏移量:字符"格式中的字符部分)
    POS=${POS%%:*}

    # ============================================================
    # 提取配置数据
    # tail -c+ 从指定字节位置开始读取
    # +8 是跳过8字节的头部(长度信息)
    # zcat 解压gzip压缩的数据
    # ============================================================
    tail -c+"$((POS + 8))" "${lIMG_}" | zcat > "${TMP1}" 2> /dev/null

    # 检查解压是否成功
    # zcat成功返回0, 尾部有垃圾数据返回2, 失败返回1
    if [[ $? != 1 ]]; then  # exit status must be 0 or 2 (trailing garbage warning)
      # 如果启用了strict mode,暂时禁用以处理可能的错误
      [[ "${STRICT_MODE}" -eq 1 ]] && set +e

      # 检查临时文件是否创建成功
      if ! [[ -f "${TMP1}" ]]; then
        return
      fi

      # 计算提取配置的MD5,用于去重
      lCFG_MD5=$(md5sum "${TMP1}" | awk '{print $1}')

      # 检查是否已提取过相同配置
      if [[ ! " ${KCFG_MD5_ARR[*]} " =~ ${lCFG_MD5} ]]; then
        # 保存提取的配置到日志目录
        KCONFIG_EXTRACTED="${LOG_PATH_MODULE}/kernel_config_extracted_$(basename "${lIMG_}").log"
        cp "${TMP1}" "${KCONFIG_EXTRACTED}"
        # 添加到已处理列表
        KCFG_MD5_ARR+=("${lCFG_MD5}")
        # return value of 4 means we are done and we are going back to the main function of this module for the next file
        # 返回4表示成功,调用者根据此值退出
        return 4
      else
        # 配置已存在,记录并返回
        write_log "[*] Firmware binary ${ORANGE}${IMG}${NC} already analyzed .. skipping" "${lLOG_FILE}"
        return 4
      fi
    fi
  fi
}

# ==========================================================================================
# try_decompress - 尝试使用特定压缩格式解压并提取配置
#
# 功能:
#   对于使用特定压缩格式(gzip/xz/bzip2/lzma/lzop/lz4/zstd)的内核镜像
#   尝试找到压缩数据的起始位置,解压后再调用dump_config提取配置
#
# 参数:
#   $1 - 压缩格式的魔术签名(八进制转义序列)
#   $2 - 用于定位的字符序列
#   $3 - 解压命令(如 gunzip, unxz 等)
#   $4 - lLOG_FILE: 日志文件路径(隐式传递)
#
# 处理流程:
#   1. 在镜像中查找压缩签名的位置
#   2. 从签名位置开始,使用指定的解压命令解压
#   3. 对解压后的数据调用dump_config尝试提取配置
#   4. 如果提取成功(返回4),则退出
# ==========================================================================================
try_decompress() {
  # 源码参考: https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-ikconfig
  local lLOG_FILE="${1:-}"

  export POS=""
  # 遍历所有匹配到的压缩签名位置
  for POS in $(tr "$1\n$2" "\n$2=" < "${IMG}" | grep -abo "^$2"); do
    # 提取字节偏移量
    POS=${POS%%:*}
    # 从压缩数据起始位置开始,使用指定命令解压,结果存入TMP2
    tail -c+"${POS}" "${IMG}" | "${3}" > "${TMP2}" 2> /dev/null
    # 对解压后的数据尝试提取配置
    dump_config "${TMP2}" "${lLOG_FILE}"
    # 如果提取成功(返回4),退出循环
    [[ $? -eq 4 ]] && return 4
  done
}

# ==========================================================================================
# check_kconfig - 检查内核配置的安全加固设置
#
# 功能:
#   使用kernel-hardening-checker工具分析提取的内核配置文件
#   检测安全相关的内核加固选项,并生成安全评估报告
#
# 检查内容包括:
#   - 内核符号隐藏 (kptr_restrict, dmesg_restrict)
#   - 内核内存保护 (SMEP, SMAP, NX bit)
#   - 内核堆栈保护 (stack-protector)
#   - 内核只读内存保护 (rodata)
#   - 内核地址空间布局随机化 (KASLR)
#   - 内核调试接口控制
#   - 内核模块加载控制
#   - 网络安全相关配置
#   - 用户空间访问控制
#
# 参数:
#   $1 - lKCONFIG_FILE: 内核配置文件路径
#   $2 - lKCONFIG_ARCH: 处理器架构(用于选择对应的检查规则)
#   $3 - lLOG_FILE: 日志文件路径
#
# 依赖工具:
#   - kernel-hardening-checker: 内核安全配置检查工具
#     来自: https://github.com/a13xp0p0v/kernel-hardening-checker
# ==========================================================================================
check_kconfig() {
  local lKCONFIG_FILE="${1:-}"        # 内核配置文件路径
  local lKCONFIG_ARCH="${2:-}"        # 处理器架构
  local lLOG_FILE="${3:-}"            # 日志文件

  # 硬编码检查器路径
  local lKCONF_HARD_CHECKER="${EXT_DIR}/kconfig-hardened-check/bin/kernel-hardening-checker"
  local lFAILED_KSETTINGS=""         # 失败的安全设置数量
  local lKCONF_LOG=""                # 检查结果日志

  # 检查硬编码检查器是否存在
  if ! [[ -e "${lKCONF_HARD_CHECKER}" ]]; then
    write_log "[-] Kernel config hardening checker not found" "${lLOG_FILE}"
    return
  fi

  # 检查内核配置文件是否存在
  if ! [[ -f "${lKCONFIG_FILE}" ]]; then
    return
  fi

  # MIPS架构目前不支持,直接返回
  if [[ "${lKCONFIG_ARCH,,}" == *"mips"* ]]; then
    write_log "[-] Architecture ${ORANGE}${lKCONFIG_ARCH}${NC} not supported by ${ORANGE}kernel-hardening-checker${NC}." "${lLOG_FILE}"
    return
  fi

  # 记录开始检查
  write_log "[*] Testing kernel configuration file ${ORANGE}${lKCONFIG_FILE}${NC} with kconfig-hardened-check (architecture ${lKCONFIG_ARCH})." "${lLOG_FILE}"

  # 创建检查结果日志文件
  lKCONF_LOG="${LOG_PATH_MODULE}/kconfig_hardening_check_$(basename "${lKCONFIG_FILE}")_${RANDOM}.log"

  # 执行内核安全配置检查
  # -c: 指定配置文件路径
  # tee -a: 同时输出到日志文件和标准输出
  "${lKCONF_HARD_CHECKER}" -c "${lKCONFIG_FILE}" | tee -a "${lKCONF_LOG}" || true

  # 分析检查结果
  if [[ -f "${lKCONF_LOG}" ]]; then
    # 统计失败的安全设置数量
    lFAILED_KSETTINGS=$(grep -c "FAIL: " "${lKCONF_LOG}" || true)

    # 如果存在失败项,记录警告
    if [[ "${lFAILED_KSETTINGS}" -gt 0 ]]; then
      write_log "[+] Found ${ORANGE}${lFAILED_KSETTINGS}${GREEN} security related kernel settings which should be reviewed - ${ORANGE}$(print_path "${lKCONFIG_FILE}")${NC}" "${lLOG_FILE}"
      # 添加详细检查日志链接
      write_link "${lKCONF_LOG}" "${lLOG_FILE}"
      write_log "" "${lLOG_FILE}"
      # 记录统计数据
      write_log "[*] Statistics:${lFAILED_KSETTINGS}" "${lLOG_FILE}"
    fi
  fi
}
