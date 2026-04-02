#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Tests the emulated live system which is build and started in L10 with Metasploit
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# ================================================#
# 模块：L35_metasploit_check.sh                    #
# 功能：使用Metasploit框架对仿真系统进行漏洞测试  #
# 描述：该模块利用Metasploit框架对L10模块启动的  #
#       仿真系统进行主动漏洞检测和利用尝试         #
# 注意：这是一个实验性模块，需要通过-Q开关单独激活  #
#       建议在docker或虚拟化环境中使用             #
# ================================================#

L35_metasploit_check() {
  # 初始化模块结束标志
  local lMODULE_END=0
  
  # 检查系统是否在线且TCP连接正常
  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    # 检查Metasploit是否安装
    if ! command -v msfconsole >/dev/null; then
      print_output "[-] Metasploit not available - Not performing Metasploit checks"
      return
    fi
    # 检查Metasploit资源脚本是否存在
    if ! [[ -f "${HELP_DIR}""/l35_msf_check.rc" ]]; then
      print_output "[-] Metasploit resource script not available - Not performing Metasploit checks"
      return
    fi

    # 初始化模块日志
    module_log_init "${FUNCNAME[0]}"
    # 打印模块标题
    module_title "Metasploit exploit checks of emulated device."
    # 预模块报告
    pre_module_reporter "${FUNCNAME[0]}"

    # 警告：非Docker环境可能存在风险
    if [[ ${IN_DOCKER} -eq 0 ]]; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    # 检查IP地址是否存在
    if [[ -v IP_ADDRESS_ ]]; then
      # 检查系统是否在线
      if ! system_online_check "${IP_ADDRESS_}"; then
        # 尝试重启仿真系统
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing Metasploit checks"
          module_end_log "${FUNCNAME[0]}" "${lMODULE_END}"
          return
        fi
      fi

      # 执行Metasploit检查
      check_live_metasploit
      lMODULE_END=1
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    module_end_log "${FUNCNAME[0]}" "${lMODULE_END}"
  fi
}

check_live_metasploit() {
  # 打印子模块标题
  sub_module_title "Metasploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC}"
  
  # 初始化变量
  local lPORTS=""
  local lPORTS_ARR=()
  local lMSF_VULN=""
  local lMSF_VULNS_VERIFIED_ARR=()
  local lMSF_CVEs_ARR=()
  local lMSF_MODULE=""
  local lARCH_END=""
  local lD_END=""

  # 从XML文件中提取开放端口
  if [[ -v ARCHIVE_PATH ]]; then
    # 从ARCHIVE_PATH中查找开放端口
    mapfile -t lPORTS_ARR < <(find "${ARCHIVE_PATH}" -name "*.xml" -exec grep -a -h "<state state=\"open\"" {} \; | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  else
    # 从L10系统仿真日志中查找开放端口
    print_output "[-] Warning: No ARCHIVE_PATH found"
    mapfile -t lPORTS_ARR < <(find "${LOG_DIR}"/l10_system_emulation/ -name "*.xml" -exec grep -a -h "<state state=\"open\"" {} \; | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  fi
  
  # 检查是否有开放端口
  if [[ "${#lPORTS_ARR[@]}" -eq 0 ]]; then
    print_output "[-] No open ports identified ..."
    return
  fi

  # 格式化端口列表
  printf -v lPORTS "%s " "${lPORTS_ARR[@]}"
  lPORTS=${lPORTS//\ /,}
  lPORTS="${lPORTS%,}"
  print_output "[*] Testing system with IP address ${ORANGE}${IP_ADDRESS_}${NC} and ports ${ORANGE}${lPORTS}${NC}."

  # 清理环境变量，避免Metasploit解析问题
  export PORT=""
  # 转换lD_END为小写
  lD_END="${lD_END,,}"
  # 调整字节序表示
  if [[ "${lD_END}" == "el" ]]; then lD_END="le"; fi
  if [[ "${lD_END}" == "eb" ]]; then lD_END="be"; fi
  # 构建架构和字节序的组合
  lARCH_END="${ARCH,,}""${lD_END,,}"

  # 执行Metasploit检查，设置60分钟超时
  timeout --signal SIGINT -k 60 60m msfconsole -q -n -r "${HELP_DIR}"/l35_msf_check.rc "${IP_ADDRESS_}" "${lPORTS}" "${lARCH_END}" | tee -a "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt || true

  # 检查Metasploit结果
  if [[ -f "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt ]] && [[ $(grep -a -i -c "Vulnerability identified for module" "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt) -gt 0 ]]; then
    # 写入CSV日志头
    write_csv_log "Source" "Module" "CVE" "ARCH_END" "IP_ADDRESS" "PORTS"
    print_ln
    print_output "[+] Metasploit results for verification" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
    
    # 提取已验证的漏洞
    mapfile -t lMSF_VULNS_VERIFIED_ARR < <(grep -a -i "Vulnerability identified for module" "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt || true)
    
    # 处理每个已验证的漏洞
    for lMSF_VULN in "${lMSF_VULNS_VERIFIED_ARR[@]}"; do
      local lMSF_CVE=""
      # 提取Metasploit模块名称
      lMSF_MODULE="$(echo "${lMSF_VULN}" | sed 's/.*module\ //' | sed 's/\ -\ .*//')"
      # 从Metasploit数据库中查找对应的CVE
      mapfile -t lMSF_CVEs_ARR < <(grep "${lMSF_MODULE}" "${MSF_DB_PATH}" | cut -d: -f2 || true)
      # 格式化CVE列表
      printf -v lMSF_CVE "%s " "${lMSF_CVEs_ARR[@]}"
      lMSF_CVE="${lMSF_CVE%\ }"
      
      if [[ -n "${lMSF_CVE}" ]]; then
        # 打印带有CVE的漏洞信息
        print_output "[+] Vulnerability verified: ${ORANGE}${lMSF_MODULE}${GREEN} / ${ORANGE}${lMSF_CVE}${GREEN}."
        # 写入Metasploit模块的GitHub链接
        write_link "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/${lMSF_MODULE}.rb"
        # 稍后为每个CVE写入CSV条目
      else
        # 打印没有CVE的漏洞信息
        print_output "[+] Vulnerability verified: ${ORANGE}${lMSF_MODULE}${GREEN}."
        # 写入Metasploit模块的GitHub链接
        write_link "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/${lMSF_MODULE}.rb"
        lMSF_CVE="NA"
        # 直接写入CSV条目
        write_csv_log "Metasploit framework" "${lMSF_MODULE}" "${lMSF_CVE}" "${lARCH_END}" "${IP_ADDRESS_}" "${lPORTS}"
      fi
      
      # 为每个CVE写入CSV条目
      for lMSF_CVE in "${lMSF_CVEs_ARR[@]}"; do
        write_csv_log "Metasploit framework" "${lMSF_MODULE}" "${lMSF_CVE}" "${lARCH_END}" "${IP_ADDRESS_}" "${lPORTS}"
      done
    done

    # 为结果添加颜色
    sed -i -r 's/.*Vulnerability identified.*/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt
    sed -i -r 's/.*Session state.*for module.*/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt
    sed -i -r 's/Active sessions/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt
    sed -i -r 's/Via:\ .*/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt

    print_ln

    # 检查是否有活动会话
    if grep -q "Active sessions" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"; then
      print_ln
      print_output "[+] Possible Metasploit sessions for verification:" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
      # 有时需要两个print_ln才能在web报告中显示一个
      print_ln
      print_ln
      # 打印会话输出
      sed -n '/Active sessions/,/Stopping all jobs/p' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt | tee -a "${LOG_FILE}" || true
      print_ln
    elif grep -q "session .* opened" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"; then
      print_ln
      print_output "[+] Possible Metasploit sessions for verification - check the log" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
      print_ln
    else
      print_output "[-] No Metasploit session detected"
    fi
  elif [[ -f "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt ]]; then
    # 仅在web报告中链接日志文件
    print_output "[-] No Metasploit results detected" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
  else
    print_output "[-] No Metasploit results detected"
  fi
  
  # 打印完成信息
  print_output "[*] Metasploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC} finished"
}
