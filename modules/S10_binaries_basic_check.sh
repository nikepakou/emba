#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  二进制文件关键函数检测模块
#               EMBA中最早存在的模块之一
#               识别使用危险函数的二进制文件
#               建立优先分析区域的排名
#
# 工作流程:
#   1. 从config/functions.cfg加载危险函数列表
#   2. 遍历所有ELF文件
#   3. 使用readelf提取符号表
#   4. 匹配危险函数 (如system, exec, strcpy等)
#   5. 输出包含危险函数的二进制文件列表
#
# 依赖配置: config/functions.cfg (危险函数列表)
#
# 依赖工具: readelf, strings, grep, sed
#
# 环境变量:
#   - VUL_FUNC_GREP: 危险函数grep命令数组
#   - P99_CSV_LOG: P99模块生成的CSV日志

S10_binaries_basic_check()
{
  # S10二进制基础检查主函数
  # 检测二进制文件中的关键/危险函数
  # EMBA中最早存在的模块之一，用于识别潜在的安全风险

  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for critical functions"
  pre_module_reporter "${FUNCNAME[0]}"

  local lCOUNTER=0
  local lBIN_COUNT=0
  local lVULNERABLE_FUNCTIONS=""
  local lBINARY=""
  local lVUL_FUNC_RESULT_ARR=()
  local lVUL_FUNC=""

  # 第1步: 从配置文件加载危险函数列表
  lVULNERABLE_FUNCTIONS="$(config_list "${CONFIG_DIR}""/functions.cfg")"

  # nosemgrep
  local IFS=" "
  IFS=" " read -r -a VUL_FUNC_GREP <<<"$( echo -e "${lVULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ -e /g')"

  # 第2步: 检查配置文件是否有效
  if [[ "${lVULNERABLE_FUNCTIONS}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "${lVULNERABLE_FUNCTIONS}" ]] ; then
    print_output "[*] Interesting functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"

    # 第3步: 遍历所有ELF文件，检测危险函数
    while read -r lBINARY; do
      lBIN_COUNT=$((lBIN_COUNT+1))
      # 使用readelf提取动态符号表，匹配危险函数
      mapfile -t lVUL_FUNC_RESULT_ARR < <(readelf -W -s --use-dynamic "${lBINARY}" 2> /dev/null | grep -we "${VUL_FUNC_GREP[@]}" | grep -v "file format" || true)

      # 回退方案: 如果动态段无法使用，则检查静态重定位表
      # Fallback: just in case the dynamic section not working -> check static relocations
      if [[ "${#lVUL_FUNC_RESULT_ARR[@]}" -eq 0 ]] ; then
        mapfile -t lVUL_FUNC_RESULT_ARR < <(readelf -W -s "${lBINARY}" 2> /dev/null | grep -we "${VUL_FUNC_GREP[@]}" | grep -v "file format" || true)
      fi

      # 第4步: 输出包含危险函数的二进制文件信息
      if [[ "${#lVUL_FUNC_RESULT_ARR[@]}" -gt 0 ]] ; then
        print_ln
        print_output "[+] Interesting function in ""$(print_path "${lBINARY}")"" found:"
        for lVUL_FUNC in "${lVUL_FUNC_RESULT_ARR[@]}" ; do
          # shellcheck disable=SC2001
          lVUL_FUNC="$(echo "${lVUL_FUNC}" | sed -e 's/[[:space:]]\+/\t/g')"
          print_output "$(indent "${lVUL_FUNC}")"
        done
        lCOUNTER=$((lCOUNTER+1))
      fi
    done < <(grep ";ELF" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
    print_ln
    print_output "[*] Found ""${ORANGE}${lCOUNTER}${NC}"" binaries with interesting functions in ""${ORANGE}${lBIN_COUNT}${NC}"" files (vulnerable functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ /g' )"")"
  fi

  module_end_log "${FUNCNAME[0]}" "${lCOUNTER}"
}
