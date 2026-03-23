#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
# 嵌入式Linux固件分析器
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

# Description:  深度密码搜索模块
#               在固件文件中搜索指定的密码模式
#               查找可能包含密码哈希值的文件
#
# 依赖: config/deep_password_search.cfg

# 模块函数：S107_deep_password_search
# 功能：深度分析文件以查找密码哈希值
S107_deep_password_search()
{
  # 初始化模块日志
  module_log_init "${FUNCNAME[0]}"
  # 设置模块标题
  module_title "Deep analysis of files for password hashes"
  # 运行模块前的报告
  pre_module_reporter "${FUNCNAME[0]}"

  # 密码哈希配置文件路径
  local lPW_HASH_CONFIG="${CONFIG_DIR}"/password_regex.cfg
  # 密码哈希计数器
  local lPW_COUNTER=0
  # 临时变量：文件路径
  local lPW_PATH=""
  # 临时变量：密码哈希数组
  local lPW_HASHES_ARR=()
  # 临时变量：单个密码哈希
  local lPW_HASH=""

  # 使用find命令在固件路径中查找所有文件
  # -xdev: 不跨越文件系统边界
  # -type f: 只查找文件
  # -print0: 使用null字符分隔文件名（处理包含空格的文件名）
  # xargs -r -0 -P 16: 使用null字符分隔输入，最多并行16个进程
  # sh -c 'grep ...': 对每个文件执行grep搜索
  # --color: 高亮显示匹配内容
  # -n: 显示行号
  # -a: 将二进制文件视为文本文件
  # -E: 使用扩展正则表达式
  # -H: 显示文件名
  # -f: 从配置文件读取模式
  # 将结果输出到临时文件pw_hashes.txt
  find "${FIRMWARE_PATH}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep --color -n -a -E -H -f '"${lPW_HASH_CONFIG}"' "%" || true' > "${TMP_DIR}"/pw_hashes.txt || true

  # 如果找到密码哈希
  if [[ $(wc -l < "${TMP_DIR}"/pw_hashes.txt) -gt 0 ]]; then
    # 打印找到的密码哈希值
    print_output "[+] Found the following password hash values:"
    # 写入CSV日志的表头
    write_csv_log "PW_PATH" "PW_HASH"
    
    # 逐行读取pw_hashes.txt中的结果
    while read -r lPW_HASH; do
      # 提取文件路径（去除哈希值部分，保留路径）
      # lPW_HASH格式: 文件路径:行号:哈希值
      # ${lPW_HASH/:*} 表示从第一个冒号开始截取到行尾，只保留文件路径
      lPW_PATH="${lPW_HASH/:*}"
      
      # 从文件中提取所有匹配密码模式的字符串
      # strings: 从二进制文件中提取可打印字符串
      # grep: 使用密码配置文件中的模式过滤
      mapfile -t lPW_HASHES_ARR < <(strings "${lPW_PATH}" | grep --color -a -E -f "${lPW_HASH_CONFIG}" || true)
      
      # 遍历找到的所有密码哈希
      for lPW_HASH in "${lPW_HASHES_ARR[@]}"; do
        # 打印找到的密码哈希信息
        # 包括文件路径和哈希值
        print_output "[+] PATH: ${ORANGE}$(print_path "${lPW_PATH}")${GREEN}\t-\tHash: ${ORANGE}${lPW_HASH}${GREEN}."
        # 写入CSV日志
        write_csv_log "${lPW_PATH}" "${lPW_HASH}"
        # 增加计数器
        ((lPW_COUNTER+=1))
      done
    done < "${TMP_DIR}"/pw_hashes.txt

    # 打印空行
    print_ln
    # 打印找到的密码哈希总数
    print_output "[*] Found ${ORANGE}${lPW_COUNTER}${NC} password hashes."
  fi
  
  # 写入空行到日志
  write_log ""
  # 写入统计信息到日志
  write_log "[*] Statistics:${lPW_COUNTER}"

  # 结束模块日志，记录找到的密码哈希数量
  module_end_log "${FUNCNAME[0]}" "${lPW_COUNTER}"
}
