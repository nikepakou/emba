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

# Description:  软件包SBOM(软件物料清单)分析模块
#               在已知位置搜索包管理信息
#               生成固件中软件包的SBOM清单
#
# 工作流程:
#   1. 加载子模块 (S08_main_package_sbom_modules目录)
#   2. 识别发行版类型
#   3. 并行执行各包管理器检测模块
#   4. 生成统一的SBOM报告
#
# 支持的包管理器:
#   - Debian系: dpkg, apt
#   - RedHat系: rpm, yum
#   - Alpine: apk
#   - OpenWRT: opkg
#   - 及其他常见嵌入式Linux包管理系统
#
# 依赖工具: jq (JSON处理), find, uuidgen, jo (JSON对象创建)
#
# 环境变量:
#   - S08_CSV_LOG: CSV格式的SBOM日志路径
#   - SBOM_LOG_PATH: SBOM输出目录
#   - THREADED: 是否启用多线程 (1=启用, 0=禁用)
#   - S08_MODULES_ARR: 包管理器检测模块数组
#   - MAX_MOD_THREADS: 最大并行线程数

S08_main_package_sbom() {
  # 模块日志初始化，设置模块名称为函数名
  module_log_init "${FUNCNAME[0]}"
  # 输出模块标题
  module_title "EMBA central package SBOM environment"
  # 预模块报告器，记录模块开始状态
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lWAIT_PIDS_S08_ARR=()
  local lOS_IDENTIFIED=""
  local lS08_SUBMODULE_PATH="${MOD_DIR}/S08_main_package_sbom_modules"
  # 导出重复包日志路径，用于记录重复的包信息
  export S08_DUPLICATES_LOG="${LOG_PATH_MODULE}/SBOM_duplicates.log"
  local lS08_SUBMODULES_FILES_ARR=()
  local lS08_SUBMODULE=""

  # 第1步: 动态加载S08_main_package_sbom_modules目录下的所有子模块
  # 子模块包括各种包管理器的检测模块 (dpkg, rpm, apk, opkg等)
  mapfile -t lS08_SUBMODULES_FILES_ARR < <(find "${lS08_SUBMODULE_PATH}" -type f -name "S08_*.sh")
  for lS08_SUBMODULE in "${lS08_SUBMODULES_FILES_ARR[@]}"; do
    print_output "[*] SBOM - loading sub module ${lS08_SUBMODULE}" "no_log"
    # shellcheck source=/dev/null
    source "${lS08_SUBMODULE}"
  done

  # 检查CSV日志文件是否存在有效数据
  # shellcheck disable=SC2153
  check_for_s08_csv_log "${S08_CSV_LOG}"

  # 第2步: 识别固件发行版类型 (通过distri_check函数)
  # 返回值可能为: debian, redhat, alpine, openwrt, fedora等
  lOS_IDENTIFIED=$(distri_check)

  local lS08_MODULE=""

  # 第3步: 并行或串行执行各包管理器检测模块
  if [[ ${THREADED} -eq 1 ]]; then
    # 多线程模式: 并行启动所有包管理器检测模块
    for lS08_MODULE in "${S08_MODULES_ARR[@]}"; do
      print_output "[*] SBOM - starting ${lS08_MODULE}" "no_log"
      # 后台运行检测模块，传入发行版类型参数
      "${lS08_MODULE}" "${lOS_IDENTIFIED}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )
    done
    # 等待所有后台进程完成
    wait_for_pid "${lWAIT_PIDS_S08_ARR[@]}"
  else
    # 单线程模式: 逐个执行检测模块
    for lS08_MODULE in "${S08_MODULES_ARR[@]}"; do
      "${lS08_MODULE}" "${lOS_IDENTIFIED}"
    done
  fi

  # 第4步: 构建软件包依赖树
  # 分析各包管理器检测出的软件包之间的依赖关系
  build_dependency_tree

  # 检查CSV日志是否有内容，决定模块完成状态
  # shellcheck disable=SC2153
  [[ -s "${S08_CSV_LOG}" ]] && lNEG_LOG=1
  # 记录模块完成日志
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

build_dependency_tree() {
  # 构建软件包依赖树函数
  # 扫描所有SBOM组件JSON文件，分析软件包之间的依赖关系

  # 检查SBOM日志目录是否存在，不存在则直接返回
  if [[ ! -d "${SBOM_LOG_PATH}" ]]; then
    return
  fi

  # 输出子模块标题
  sub_module_title "SBOM dependency tree builder"

  local lSBOM_COMPONENT_FILES_ARR=()
  local lSBOM_COMP=""

  local lWAIT_PIDS_S08_DEP_ARR=()

  # 查找SBOM目录下所有JSON组件文件
  # 每个文件代表一个已识别软件包的SBOM信息
  mapfile -t lSBOM_COMPONENT_FILES_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -type f -name "*.json")

  # 遍历每个组件文件，并行构建其依赖关系
  for lSBOM_COMP in "${lSBOM_COMPONENT_FILES_ARR[@]}"; do
    [[ ! -f "${lSBOM_COMP}" ]] && continue
    # 为加速依赖树构建，对每个组件文件启用多线程处理
    # 生成的依赖关系保存在: "${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lSBOM_COMP_REF}.json"
    # 这些文件可在f15模块中汇总分析
    create_comp_dep_tree_threader "${lSBOM_COMP}" &
    lWAIT_PIDS_S08_DEP_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_DEP_ARR
  done
  # 等待所有依赖分析进程完成
  wait_for_pid "${lWAIT_PIDS_S08_DEP_ARR[@]}"

  # 输出依赖分析结果
  if [[ -d "${SBOM_LOG_PATH}/SBOM_deps" ]]; then
    print_output "[+] SBOM dependency results" "" "${SBOM_LOG_PATH}/SBOM_dependencies.txt"
  else
    print_output "[*] No SBOM dependency results available"
  fi
}

create_comp_dep_tree_threader() {
  # 线程化创建组件依赖树函数
  # 分析单个SBOM组件JSON文件，提取其依赖关系
  #
  # 参数:
  #   $1 - lSBOM_COMP: 当前正在分析的SBOM组件JSON文件路径
  local lSBOM_COMP="${1:-}"

  local lSBOM_COMP_DEPS_ARR=()
  local lSBOM_COMP_DEPS_FILES_ARR=()
  local lSBOM_COMP_NAME=""       # 组件名称
  local lSBOM_COMP_REF=""        # 组件BomRef (唯一标识符)
  local lSBOM_COMP_VERS=""       # 组件版本
  local lSBOM_COMP_SOURCE=""     # 组件来源 (如debian_pkg_mgmt)
  local lSBOM_COMP_DEP=""        # 依赖项名称
  local lSBOM_DEP_SOURCE_FILES_ARR=()
  local lSBOM_COMP_SOURCE_FILE=""
  local lSBOM_COMP_SOURCE_REF=""
  local lSBOM_INVALID_COM_REF=""

  # 提取所需的元数据
  # name: 组件名称
  # bom-ref: 组件的唯一引用标识符
  # version: 组件版本 (用于显示，可选)
  lSBOM_COMP_NAME=$(jq -r .name "${lSBOM_COMP}" || true)
  lSBOM_COMP_REF=$(jq -r '."bom-ref"' "${lSBOM_COMP}" || true)
  lSBOM_COMP_VERS=$(jq -r .version "${lSBOM_COMP}" || true)
  # group字段用于确保只检查匹配的来源 (如: 检查debian包时只对debian源)
  lSBOM_COMP_SOURCE=$(jq -r .group "${lSBOM_COMP}" || true)

  # 如果组件名称或引用为空，则跳过处理
  if [[ -z "${lSBOM_COMP_NAME}" || -z "${lSBOM_COMP_REF}" ]]; then
    return
  fi

  # 记录源文件和组件基本信息到临时日志
  write_log "[*] Source file: ${lSBOM_COMP}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
  write_log "[*] Component: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_VERS} / ${lSBOM_COMP_SOURCE} / ${lSBOM_COMP_REF}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"

  # 从组件JSON中提取依赖项列表
  # 使用jq筛选properties中name以":dependency"结尾的条目
  mapfile -t lSBOM_COMP_DEPS_FILES_ARR < <(jq -rc '.properties[] | select(.name | endswith(":dependency")).value' "${lSBOM_COMP}" || true)
  # 如果没有依赖项，直接返回
  if [[ "${#lSBOM_COMP_DEPS_FILES_ARR[@]}" -eq 0 ]]; then
    return
  fi

  # 创建依赖输出目录
  if [[ ! -d "${SBOM_LOG_PATH%\/}/SBOM_deps" ]]; then
    mkdir "${SBOM_LOG_PATH%\/}/SBOM_deps" 2>/dev/null || true
  fi

  # 遍历当前组件的每个依赖项
  for lSBOM_COMP_DEP in "${lSBOM_COMP_DEPS_FILES_ARR[@]}"; do
    # 清理依赖项名称中的特殊字符
    # 移除单引号、括号内容、空格前缀等
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP//\'}"
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP/\ *}"
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP/\(*}"

    # 在同源(同包管理器)的组件文件中查找该依赖项
    # 例如: 在debian_pkg_mgmt_*.json文件中查找名为lSBOM_COMP_DEP的组件
    mapfile -t lSBOM_DEP_SOURCE_FILES_ARR < <(grep -l "name\":\"${lSBOM_COMP_DEP}\"" "${SBOM_LOG_PATH}"/"${lSBOM_COMP_SOURCE}"_* || true)

    # 如果找到依赖项的组件文件，记录其BomRef UUID
    # 如果未找到依赖项，记录为无效引用
    if [[ "${#lSBOM_DEP_SOURCE_FILES_ARR[@]}" -gt 0 ]]; then
      for lSBOM_COMP_SOURCE_FILE in "${lSBOM_DEP_SOURCE_FILES_ARR[@]}"; do
        # 获取依赖项的BomRef
        lSBOM_COMP_SOURCE_REF=$(jq -r '."bom-ref"' "${lSBOM_COMP_SOURCE_FILE}" || true)
        write_log "[*] Component dependency found: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_REF} -> ${lSBOM_COMP_DEP} / ${lSBOM_COMP_SOURCE_REF:-NA}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
        # 避免重复添加依赖引用
        if ! [[ "${lSBOM_COMP_DEPS_ARR[*]}" == *"${lSBOM_COMP_SOURCE_REF}"* ]]; then
          lSBOM_COMP_DEPS_ARR+=("-s" "${lSBOM_COMP_SOURCE_REF}")
        fi
      done
    else
      # 依赖项未在SBOM中找到，生成唯一标识符
      write_log "[*] Component dependency without reference found: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_REF} -> ${lSBOM_COMP_DEP} / No valid reference available" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
      # 使用UUID生成唯一标识符
      lSBOM_INVALID_COM_REF="$(uuidgen)"
      lSBOM_COMP_DEPS_ARR+=("-s" "${lSBOM_INVALID_COM_REF}-NO_VALID_REF-${lSBOM_COMP_DEP}")
    fi
  done
  write_log "" "${SBOM_LOG_PATH}/SBOM_dependencies.txt"

  # 将临时日志追加到总体依赖日志，并清理临时文件
  cat "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt" >> "${SBOM_LOG_PATH}/SBOM_dependencies.txt"
  rm "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt" || true

  # 生成依赖关系JSON文件
  # 格式: {"ref": "组件BomRef", "dependsOn": ["依赖1BomRef", "依赖2BomRef", ...]}
  jo -p ref="${lSBOM_COMP_REF}" dependsOn="$(jo -a -- "${lSBOM_COMP_DEPS_ARR[@]}")" >> "${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lSBOM_COMP_REF}".json
}

clean_package_details() {
  # 清理包详情字符串函数
  # 移除特殊字符，规范化包信息格式，使其适合在SBOM中使用
  #
  # 参数:
  #   $1 - 要清理的包详情字符串
  # 返回: 清理后的字符串
  local lCLEAN_ME_UP="${1}"

  # 安全回显，防止注入
  lCLEAN_ME_UP=$(safe_echo "${lCLEAN_ME_UP}")
  # 移除所有非可打印字符
  lCLEAN_ME_UP="${lCLEAN_ME_UP//[![:print:]]/}"
  # 移除双引号
  lCLEAN_ME_UP="${lCLEAN_ME_UP/\"}"
  # 启用扩展通配符模式
  # Turn on extended globbing
  shopt -s extglob
  # 移除特殊符号: [ ] ' " ; # % / < > ( )
  lCLEAN_ME_UP=${lCLEAN_ME_UP//+([\[\'\"\;\#\%\/\<\>\(\)\]])}
  # 移除前导空格
  lCLEAN_ME_UP=${lCLEAN_ME_UP##+( )}
  # 移除尾随空格
  lCLEAN_ME_UP=${lCLEAN_ME_UP%%+( )}
  # 将空格替换为下划线
  lCLEAN_ME_UP=${lCLEAN_ME_UP//\ /_}
  # 合并连续的下划线
  lCLEAN_ME_UP=${lCLEAN_ME_UP//+(_)/_}
  # 关闭扩展通配符模式
  # Turn off extended globbing
  shopt -u extglob
  # 转换为小写
  lCLEAN_ME_UP=${lCLEAN_ME_UP,,}
  # 将逗号替换为点号
  lCLEAN_ME_UP=${lCLEAN_ME_UP//,/\.}
  echo "${lCLEAN_ME_UP}"
}

clean_package_versions() {
  # 清理软件包版本号函数
  # 标准化版本号格式，移除发行版特定的后缀
  #
  # 参数:
  #   $1 - lVERSION: 原始版本号字符串
  # 返回: 清理后的标准化版本号
  #
  # 示例输入/输出:
  #   1.2.3-4      -> 1.2.3
  #   1.2.3-0kali1bla -> 1.2.3
  #   1.2.3-unknown -> 1.2.3
  #   1.2.3-1ubuntu20 -> 1.2.3
  local lVERSION="${1:-}"
  local lSTRIPPED_VERSION=""

  # 通常获取的版本格式如: 1.2.3-4 或 1.2.3-0kali1bla 或 1.2.3-unknown
  # 这是一个快速清理版本标识符的方法，未来有很大的改进空间
  # this is a quick approach to clean this version identifier
  # there is a lot of room for future improvement

  # 1. 移除末尾的数字版本后缀 (如: 1.2.3-4 -> 1.2.3)
  lSTRIPPED_VERSION=$(safe_echo "${lVERSION}" | sed -r 's/-[0-9]+$//g')
  # 2. 移除-unknown后缀
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-unknown$//g')
  # 3. 移除Kali Linux版本后缀 (如: 1.2.3-0kali1bla -> 1.2.3)
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+kali[0-9]+.*$//g')
  # 4. 移除Ubuntu版本后缀
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+ubuntu[0-9]+.*$//g')
  # 5. 移除build版本号
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+build[0-9]+$//g')
  # 6. 移除补丁版本号 (如: 1.2-3.4 -> 1.2)
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[0-9]+$//g')
  # 7. 移除测试版本号 (如: 1.2-3.4a5 -> 1.2)
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[a-d][0-9]+$//g')
  # 8. 清理端口号格式
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/:[0-9]:/:/g')
  # 9. 移除前导数字
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/^[0-9]://g')
  # 10. 将逗号替换为点号
  lSTRIPPED_VERSION=${lSTRIPPED_VERSION//,/\.}
  # 11. 移除所有非可打印字符
  echo "${lSTRIPPED_VERSION//[![:print:]]/}"
}
