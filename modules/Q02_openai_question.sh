#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Benedikt Kuehne

# ==========================================================================================
# 模块: Q02_openai_question (OpenAI 问答模块)
#
# 描述:
#   该模块使用 OpenAI API 对固件中的脚本进行 AI 辅助分析
#   主要功能包括:
#   1. 监控其他模块生成的 GPT 问题 CSV 文件
#   2. 按优先级处理 GPT 问题
#   3. 调用 OpenAI ChatGPT API 进行代码分析
#   4. 处理 API 响应和错误
#   5. 存储 AI 分析结果
#
# 工作流程:
#   - 等待主日志文件创建（分析开始）
#   - 等待问题 CSV 文件生成（其他模块写入问题）
#   - 持续处理问题直到测试阶段结束
#   - 对每个问题调用 ChatGPT API
#   - 处理响应并存储结果
#
# 依赖:
#   - OPENAI_API_KEY: OpenAI API 密钥（必须配置）
#   - GPT_OPTION: GPT 选项开关
#   - q02_openai_question.csv: 问题 CSV 文件
#   - gpt_template.json: API 请求模板
#
# 输出:
#   - GPT 分析结果文件
#   - GPT 响应日志
#   - 错误日志
# ==========================================================================================

# ==========================================================================================
# Q02_openai_question - OpenAI 问答主函数
#
# 功能:
#   初始化模块并监控 GPT 问题队列
#   在测试阶段持续处理问题直到结束
#
# 执行流程:
#   1. 初始化模块日志系统
#   2. 检查 API 密钥和选项配置
#   3. 等待主日志文件创建
#   4. 等待问题 CSV 文件生成
#   5. 循环处理问题直到测试阶段结束
#   6. 清理 API 密钥
# ==========================================================================================
Q02_openai_question() {
  # 初始化模块日志系统
  module_log_init "${FUNCNAME[0]}"
  # ChatGPT 结果计数器，用于统计成功处理的请求数量
  export CHATGPT_RESULT_CNT=0
  
  # 检查是否启用了 GPT 选项且配置了 OpenAI API 密钥
  if [[ "${GPT_OPTION}" -gt 0 ]] && [[ -n "${OPENAI_API_KEY}" ]]; then
    # 在命令行界面和日志中打印模块标题
    module_title "AI analysis via OpenAI"
    # 预报告模块状态
    pre_module_reporter "${FUNCNAME[0]}"

    # 等待主日志文件创建（确保分析已经开始）
    while ! [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; do
      # 如果日志目录不存在，通常发生在自动化分析中删除了日志目录而模块未完成时
      if ! [[ -d "${LOG_DIR}" ]]; then
        return
      fi
      sleep 10
    done

    # 等待问题 CSV 文件生成（其他模块会将问题写入此文件）
    if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
      while ! [[ -f  "${CSV_DIR}/q02_openai_question.csv.tmp" ]]; do
        sleep 3
      done
    fi

    # 已检查的 GPT 请求数组，用于避免重复处理
    export GTP_CHECKED_ARR=()
    
    # 主循环：持续处理 GPT 问题，直到测试阶段结束
    while ! grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; do
      # 如果有可处理的问题，调用 ChatGPT
      if [[ "${CHATGPT_RESULT_CNT}" -ge 0 ]]; then
        ask_chatgpt
      fi
      sleep 2
    done

    # 清除 API 密钥以增强安全性
    unset OPENAI_API_KEY
  fi
  # 结束模块日志并记录结果数量
  module_end_log "${FUNCNAME[0]}" "${CHATGPT_RESULT_CNT}"
}

# ==========================================================================================
# ask_chatgpt - ChatGPT 问答处理函数
#
# 功能:
#   从问题 CSV 中读取待处理的 GPT 问题
#   按优先级排序并逐个处理
#   调用 OpenAI API 并处理响应
#
# 处理流程:
#   1. 创建 GPT 文件目录
#   2. 从 CSV 读取并排序问题（按优先级）
#   3. 遍历问题数组
#   4. 检查是否已处理过该问题
#   5. 准备 API 请求数据
#   6. 调用 OpenAI API
#   7. 处理响应和错误
#   8. 存储结果
# ==========================================================================================
ask_chatgpt() {
  # GPT 文件存储目录
  local lGPT_FILE_DIR="${LOG_PATH_MODULE}/gpt_files"
  # 默认优先级
  local lGPT_PRIO=3
  
  # 默认变量声明
  local lGPT_QUESTION=""              # GPT 问题文本
  local lCHATGPT_CODE=""             # ChatGPT 代码内容
  local lGPT_RESPONSE=""             # GPT 响应内容
  local lGPT_RESPONSE_CLEANED=""     # 清理后的 GPT 响应
  local lGPT_TOKENS=0               # 使用的 token 数量
  local lHTTP_CODE=200               # HTTP 响应码
  local lORIGIN_MODULE=""            # 原始模块名称
  local lGPT_SERVER_ERROR_CNT=0      # 服务器错误计数器
  local lELE_INDEX=0                # 元素索引
  local lGPT_ANCHOR=""             # GPT 锚点（唯一标识符）
  local lGPT_INPUT_FILE=""          # 输入文件名
  local lGPT_INPUT_FILE_mod=""      # 修改后的输入文件名
  local lGPT_OUTPUT_FILE=""         # 输出文件路径
  local lSCRIPT_PATH_TMP=""          # 临时脚本路径

  # 打印正在检查的脚本优先级
  print_output "[*] Checking scripts with ChatGPT that have priority ${ORANGE}${MINIMUM_GPT_PRIO}${NC} or lower" "no_log"
  
  # 如果 GPT 文件目录不存在则创建
  if ! [[ -d "${lGPT_FILE_DIR}" ]]; then
    mkdir "${lGPT_FILE_DIR}"
  fi

  # 生成 GPT 请求数组 - 按字段 3（优先级）排序
  # 该数组在每轮都会重新生成
  readarray -t Q02_OPENAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")

  # 遍历所有 GPT 问题
  for (( lELE_INDEX=0; lELE_INDEX<"${#Q02_OPENAI_QUESTIONS[@]}"; lELE_INDEX++ )); do
    # 获取当前元素
    local lELEM="${Q02_OPENAI_QUESTIONS["${lELE_INDEX}"]}"
    # 从元素中提取脚本路径（字段 1）
    lSCRIPT_PATH_TMP="$(echo "${lELEM}" | cut -d\; -f1)"

    # 由于我们总是从最高优先级的条目开始，需要检查该条目是否已经测试过
    if [[ " ${GTP_CHECKED_ARR[*]} " =~ ${lSCRIPT_PATH_TMP} ]]; then
      # 跳过已测试的条目
      continue
    fi

    # 从元素中提取各个字段
    lGPT_ANCHOR="$(echo "${lELEM}" | cut -d\; -f2)"           # 锚点（字段 2）
    lGPT_PRIO="$(echo "${lELEM}" | cut -d\; -f3)"               # 优先级（字段 3）
    lGPT_QUESTION="$(echo "${lELEM}" | cut -d\; -f4)"             # 问题（字段 4）
    lGPT_OUTPUT_FILE="$(echo "${lELEM}" | cut -d\; -f5)"            # 输出文件（字段 5）
    lGPT_TOKENS="$(echo "${lELEM}" | cut -d\; -f6)"                # Token 数量（字段 6）
    lGPT_TOKENS="${lGPT_TOKENS//cost\=/}"                         # 移除 "cost=" 前缀
    lGPT_RESPONSE="$(echo "${lELEM}" | cut -d\; -f7)"             # 响应（字段 7）
    lGPT_INPUT_FILE="$(basename "${lSCRIPT_PATH_TMP}")"          # 输入文件名
    lGPT_INPUT_FILE_mod="${lGPT_INPUT_FILE//\./}"                # 移除 "./" 前缀

    # 如果没有脚本路径则跳过
    [[ -z "${lSCRIPT_PATH_TMP}" ]] && continue

    # 特殊处理 Ghidra 反编译代码
    if [[ "${lSCRIPT_PATH_TMP}" == *"s16_ghidra_decompile_checks"* ]]; then
      # Ghidra 检查将反编译代码存储在日志目录中
      # 需要将其复制到 GPT 日志目录进行进一步处理
      print_output "[*] Ghidra decompiled code found ${lSCRIPT_PATH_TMP}" "no_log"
      [[ -f "${lSCRIPT_PATH_TMP}" ]] && cp "${lSCRIPT_PATH_TMP}" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
    else
      # 这是脚本的常规情况
      print_output "[*] Identification of ${ORANGE}${lSCRIPT_PATH_TMP} / ${lGPT_INPUT_FILE}${NC} inside ${ORANGE}${LOG_DIR}/firmware${NC}" "no_log"
      
      # 处理路径问题：移除根目录前缀
      if [[ "${lSCRIPT_PATH_TMP}" == ".""${LOG_DIR}"* ]]; then
        print_output "[*] Warning: System path is not stripped with root directory - we try to fix it now" "no_log"
        # 移除开头的 '.'
        lSCRIPT_PATH_TMP="${lSCRIPT_PATH_TMP:1}"
        # 移除 LOG_DIR
        # shellcheck disable=SC2001
        lSCRIPT_PATH_TMP="$(echo "${lSCRIPT_PATH_TMP}" | sed 's#'"${LOG_DIR}"'##')"
        print_output "[*] Stripped path ${lSCRIPT_PATH_TMP}" "no_log"
      fi
      
      # 临时修复 - TODO: 未来使用数组
      lSCRIPT_PATH_TMP="$(find "${LOG_DIR}/firmware" -wholename "*${lSCRIPT_PATH_TMP}" | head -1)"

      # 如果没有找到文件则跳过
      ! [[ -f "${lSCRIPT_PATH_TMP}" ]] && continue
      # 复制文件到 GPT 目录
      [[ -f "${lSCRIPT_PATH_TMP}" ]] && cp "${lSCRIPT_PATH_TMP}" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
    fi

    # 打印 AI 辅助分析信息
    print_output "[*] AI-Assisted analysis of script ${ORANGE}${lSCRIPT_PATH_TMP}${NC} with question ${ORANGE}${lGPT_QUESTION}${NC}" "no_log"
    print_output "[*] Current priority for testing is ${lGPT_PRIO}" "no_log"

    # 检查是否满足处理条件
    if [[ -z ${lGPT_RESPONSE} ]] && [[ ${lGPT_PRIO} -ge ${MINIMUM_GPT_PRIO} ]] && [[ "${lSCRIPT_PATH_TMP}" != '' ]]; then
      if [[ -f "${lSCRIPT_PATH_TMP}" ]]; then
        # 添加导航栏项目
        sub_module_title "AI analysis for ${lGPT_INPUT_FILE}"

        # 准备 API 请求模板
        head -n -2 "${CONFIG_DIR}/gpt_template.json" > "${TMP_DIR}/chat.json" || print_error "[-] Tmp file create error for ${lSCRIPT_PATH_TMP}"
        
        # 检查临时文件是否创建成功
        if [[ ! -f "${TMP_DIR}/chat.json" ]]; then
          print_output "[-] Temp file ${TMP_DIR}/chat.json for further analysis of ${lSCRIPT_PATH_TMP} was not created ... some Error occured"
          return
        fi

        # 准备 ChatGPT 代码：移除反斜杠、引号，移除空格和 [ASK_GPT] 标记
        lCHATGPT_CODE=$(sed 's/\\//g;s/"/\\\"/g' "${lSCRIPT_PATH_TMP}" | tr -d '[:space:]' | sed 's/\[ASK_GPT\].*//')
        
        # 如果代码太长则截断（超过 4561 字符）
        if [[ "${#lCHATGPT_CODE}" -gt 4561 ]]; then
          print_output "[*] GPT request is too big ... stripping it now" "no_log"
          lCHATGPT_CODE=$(sed 's/\\//g;s/"/\\\"/g' "${lSCRIPT_PATH_TMP}" | tr -d '[:space:]' | cut -c-4560 | sed 's/\[ASK_GPT\].*//')
        fi
        
        # 将问题和代码写入 JSON 文件，移除颜色代码
        strip_color_codes "$(printf '"%s %s"\n}]}' "${lGPT_QUESTION}" "${lCHATGPT_CODE}")" >> "${TMP_DIR}/chat.json"

        # 打印调试信息
        print_output "[*] Testing the following code with ChatGPT:" "no_log"
        cat "${lSCRIPT_PATH_TMP}"
        print_ln "no_log"
        print_output "[*] Adjusted code under test to send it to ChatGPT:" "no_log"
        cat "${TMP_DIR}/chat.json"
        print_ln "no_log"

        # 打印请求大小信息
        print_output "[*] The combined cost of OpenAI request / length is: ${ORANGE}${#lGPT_QUESTION} + ${#lCHATGPT_CODE}${NC}" "no_log"

        # 调用 OpenAI API
        lHTTP_CODE=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${OPENAI_API_KEY}" \
          -d @"${TMP_DIR}/chat.json" -o "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" --write-out "%{http_code}" || true)

        # 处理 API 错误响应
        if [[ "${lHTTP_CODE}" -ne 200 ]] ; then
          print_output "[-] Something went wrong with the ChatGPT requests"
          if [[ -f "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" ]]; then
            print_output "[-] ERROR response: $(cat "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json")"

            # 检查配额不足错误
            if jq '.error.type' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "insufficient_quota" ; then
              print_output "[-] Stopping OpenAI requests since API key has reached its quota limit"
              CHATGPT_RESULT_CNT=-1
              sleep 20
              break
            # 检查服务器错误
            elif jq '.error.type' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "server_error" ; then
              ((lGPT_SERVER_ERROR_CNT+=1))
              if [[ "${lGPT_SERVER_ERROR_CNT}" -ge 5 ]]; then
                # 超过 5 次失败则停止尝试
                print_output "[-] Stopping OpenAI requests since Server seems to be overloaded"
                CHATGPT_RESULT_CNT=-1
                sleep 20
                break
              fi
            # 检查速率限制错误
            elif jq '.error.code' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "rate_limit_exceeded" ; then
              # 速率限制处理 - 如果收到类似 "Please try again in 7m12s" 的响应
              # 则等待约 10 分钟后重试
              # 在此期间需要检查测试阶段是否仍在运行
              if jq '.error.message' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "Please try again in " ; then
                local lCNT=0
                while [[ "${lCNT}" -lt 1000 ]]; do
                  lCNT=$((lCNT+1))
                  local lTEMP_VAR="$(( "${lCNT}" % 100 ))"
                  (( "${lTEMP_VAR}" == 0 )) && print_output "[*] Rate limit handling ... sleep mode - ${lCNT}" "no_log"
                  if grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
                    break 2
                  fi
                  sleep 1
                done
                # TODO: 现在应该重做最后一次测试
              else
                print_output "[-] Stopping OpenAI requests since API key has reached its rate_limit"
                CHATGPT_RESULT_CNT=-1
                break
              fi
            fi

            # 记录服务器错误
            cat "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" >> "${lGPT_FILE_DIR}/openai_server_errors.log"
            # 重新加载问题数组
            readarray -t Q02_OPENAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")
            # 重置数组索引以从最高优先级条目重新开始
            lELE_INDEX=0
            if grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
              return
            fi
            sleep 30s
            continue
          fi
        fi

        # 检查响应文件是否存在
        if ! [[ -f "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" ]]; then
          # 捕获连接错误：(56) Recv failure: Connection reset by peer
          print_output "[-] Something went wrong with the ChatGPT request for ${lGPT_INPUT_FILE}"
          break
        fi

        # 提取 GPT 响应和 token 使用量
        lGPT_RESPONSE=("$(jq '.choices[] | .message.content' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json")")
        lGPT_RESPONSE_CLEANED="${lGPT_RESPONSE[*]//\;/}" # 移除分号
        lGPT_TOKENS=$(jq '.usage.total_tokens' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json")

        # 如果成功获取响应
        if [[ ${lGPT_TOKENS} -ne 0 ]]; then
          # 添加到已检查数组
          GTP_CHECKED_ARR+=("${lSCRIPT_PATH_TMP}")
          # 写入完成 CSV
          write_csv_gpt "${lGPT_INPUT_FILE}" "${lGPT_ANCHOR}" "${lGPT_PRIO}" "${lGPT_QUESTION}" "${lGPT_OUTPUT_FILE}" "cost=${lGPT_TOKENS}" "'${lGPT_RESPONSE_CLEANED//\'/}'"

          # 将答案存储在专用文件中以便在报告中交叉链接
          if ! [[ -d "${LOG_PATH_MODULE}"/gpt_answers ]]; then
            mkdir "${LOG_PATH_MODULE}"/gpt_answers || true
          fi
          echo "${lGPT_RESPONSE_CLEANED}" > "${LOG_PATH_MODULE}"/gpt_answers/gpt_response_"${lGPT_INPUT_FILE_mod}".log

          # 打印 OpenAI 响应
          print_ln
          echo -e "${lGPT_RESPONSE[*]}" | tee -a "${LOG_FILE}"

          # 添加适当的模块链接
          if [[ "${lGPT_OUTPUT_FILE}" == *'/csv_logs/'* ]]; then
            # 如果是 csv_logs 路径需要调整切割
            lORIGIN_MODULE="$(echo "${lGPT_OUTPUT_FILE}" | cut -d / -f4 | cut -d_ -f1)"
          elif [[ "${lGPT_OUTPUT_FILE}" == '/logs/'* ]]; then
            lORIGIN_MODULE="$(echo "${lGPT_OUTPUT_FILE}" | cut -d / -f3 | cut -d_ -f1)"
          else
            lORIGIN_MODULE="$(basename "$(dirname "${lGPT_OUTPUT_FILE}")" | cut -d_ -f1)"
          fi

          # 打印结果链接
          print_ln
          print_output "[+] Further results for ${ORANGE}${lGPT_INPUT_FILE_mod}${GREEN} available in module ${ORANGE}${lORIGIN_MODULE}${NC}" "" "${lORIGIN_MODULE}"
          print_output "[+] Analysed source file ${ORANGE}${lGPT_INPUT_FILE_mod}${GREEN}" "" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
          
          # 打印 GPT 答案文件链接
          if [[ -f "${LOG_PATH_MODULE}"/gpt_answers/gpt_response_"${lGPT_INPUT_FILE_mod}".log ]]; then
            print_output "[+] GPT answer file for ${ORANGE}${lGPT_INPUT_FILE_mod}${NC}" "" "${LOG_PATH_MODULE}"/gpt_answers/gpt_response_"${lGPT_INPUT_FILE_mod}".log
          fi

          print_ln
          # 增加结果计数器
          ((CHATGPT_RESULT_CNT+=1))
        fi
      else
        print_output "[-] Couldn't find ${ORANGE}$(print_path "${lSCRIPT_PATH_TMP}")${NC}"
      fi
    fi

    # 检查测试阶段是否结束
    if grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
      break
    fi

    # 如果不是 GPT 选项 2 则等待
    if [[ "${GPT_OPTION}" -ne 2 ]]; then
      sleep 20s
    fi

    # 重新加载 Q02 结果
    print_output "[*] Regenerate analysis array ..." "no_log"
    readarray -t Q02_OPENAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")
    # 重置数组索引以从最高优先级条目重新开始
    lELE_INDEX=0
  done

  # 清理已完成的条目
  if [[ -f "${CSV_DIR}/q02_openai_question.csv" ]]; then
    local lGPT_ENTRY_LINE=""
    while read -r lGPT_ENTRY_LINE; do
      lGPT_ANCHOR="$(echo "${lGPT_ENTRY_LINE}" | cut -d ';' -f2)"
      # 从临时文件中删除已完成的条目
      sed -i "/${lGPT_ANCHOR}/d" "${CSV_DIR}/q02_openai_question.csv.tmp"
    done < "${CSV_DIR}/q02_openai_question.csv"
  fi
}
