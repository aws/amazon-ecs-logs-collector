#!/usr/bin/env bash
#
# Copyright 2016-2018 Amazon.com, Inc. or its affiliates.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#    http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
#
# - Collects Docker daemon and Amazon ECS Container Agent logs on Amazon Linux,
#   Redhat 7, Debian 8.
# - Collects general operating system logs.
# - Optional ability to enable debug mode for the Docker daemon and Amazon ECS
#   Container Agent on Amazon Linux variants, such as the Amazon ECS-optimized
#   AMI. For usage information, see --help.

export LANG="C"
export LC_ALL="C"

# Collection configuration

# curdir is the working root of collection.
curdir="$(dirname "$0")"
# collectdir is where all collected informaton is placed under. This
# services as the top level for this script's operation.
readonly collectdir="${curdir}/collect"
# pack_name is the name of the resulting tarball. This will generally
# be collect-i-ffffffffffffffffff, where i-ffffffffffffffffff is the
# instance id.
pack_name="collect"

# Shared check variables

# info_system is where the checks' data is placed.
info_system="${collectdir}/system"
# pkgtype is the detected packaging system used on the host (eg: yum, deb)
pkgtype=''  # defined in get_pkgtype
# init_type is the operating system type used for casing check behavior.
init_type=''  # defined in get_init_type
progname='' # defined in parse_options

# Script run defaults

mode='brief' # defined in parse_options


# Common functions
# ---------------------------------------------------------------------------------------

help() {
  echo "USAGE: ${progname} [--mode=[brief|enable-debug]]"
  echo "       ${progname} --help"
  echo ""
  echo "OPTIONS:"
  echo "     --mode  Sets the desired mode of the script. For more information,"
  echo "             see the MODES section."
  echo "     --help  Show this help message."
  echo ""
  echo "MODES:"
  echo "     brief         Gathers basic operating system, Docker daemon, and Amazon"
  echo "                   ECS Container Agent logs. This is the default mode."
  echo "     enable-debug  Enables debug mode for the Docker daemon and the Amazon"
  echo "                   ECS Container Agent. Only supported on Systemd init systems"
  echo "                   and Amazon Linux."
}

parse_options() {
  local count="$#"

  progname="$0"

  for i in $(seq "$count"); do
    eval arg=\$"$i"
    # shellcheck disable=SC2154
    param="$(echo "$arg" | awk -F '=' '{print $1}' | sed -e 's|--||')"
    val="$(echo "$arg" | awk -F '=' '{print $2}')"

    case "${param}" in
      mode)
        eval "$param"="${val}"
        ;;
      help)
        help && exit 0
        ;;
      *)
        echo "Parameter not found: '$param'"
        help && exit 1
        ;;
    esac
  done
}

ok() {
  echo "ok"
}

info() {
  echo "$*"
}

try() {
  local action=$*
  echo -n "Trying to $action ... "
}

warning() {
  local reason=$*
  echo "warning: $reason"
}

failed() {
  local reason=$*
  echo "failed: $reason"
}

die() {
  echo "ERROR: $*"
  exit 1
}

is_root() {
  try "check if the script is running as root"

  if [[ "$(id -u)" != "0" ]]; then
    die "this script must be run as root!"

  fi

  ok
}

cleanup() {
  rm -rf "$collectdir" >/dev/null 2>&1
  rm -f "$curdir"/collect.tgz
}

init() {
  is_root
  try_set_instance_collectdir
  get_init_type
  get_pkgtype
}

collect_brief() {
  init
  is_diskfull
  get_common_logs
  get_kernel_logs
  get_mounts_info
  get_selinux_info
  get_iptables_info
  get_pkglist
  get_system_services
  get_docker_info
  get_docker_containers_info
  get_docker_logs
  get_docker_systemd_config
  get_docker_sysconfig
  get_docker_daemon_json
  get_ecs_agent_logs
  get_ecs_agent_info
  get_open_files
  get_os_release
  get_uname_info
  get_dmidecode_info
  get_lsmod_info
}

enable_debug() {
  is_root
  get_init_type
  enable_docker_debug
  enable_ecs_agent_debug
}

# Routines
# ---------------------------------------------------------------------------------------

# uname gets basic system and kernel information.
get_uname_info() {
  try "get uname kernel info"

  mkdir -p "$info_system"
  uname -a > "$info_system"/uname.txt

  ok
}

# dmidecode is a tool sometimes installed on VMs that provides detailed
# information about the VM hypervisor, underlying hardware, and system.
get_dmidecode_info() {
  try "get dmidecode info"

  if command -v dmidecode &>/dev/null; then
    mkdir -p "$info_system"
    dmidecode > "$info_system"/dmidecode.txt
  fi

  ok
}

# lsmod lists loadable kernel modules.
get_lsmod_info() {
  try "get lsmod info"

  if command -v lsmod &>/dev/null; then
    mkdir -p "$info_system"
    lsmod > "$info_system"/lsmod.txt
  fi

  ok
}

get_init_type() {
  try "collect system information"

  case "$(cat /proc/1/comm)" in
    systemd)
      init_type="systemd"
    ;;
    *)
      init_type="other"
    ;;
  esac

  ok
}

get_pkgtype() {
  if [[ -n "$(command -v rpm)" ]]; then
    pkgtype="rpm"
  elif [[ -n "$(command -v dpkg)" ]]; then
    pkgtype="dpkg"
  else
    pkgtype="unknown"
  fi
}

try_set_instance_collectdir() {
  try "resolve instance-id"

  if [ -f /var/lib/amazon/ssm/registration ]; then
    info "SSM managed instance detected, getting managed instance id"
    if command -v jq > /dev/null; then
      instance_id=$(jq -r ".ManagedInstanceID" < /var/lib/amazon/ssm/registration)
    fi
  fi

  if test -z "$instance_id" && command -v curl > /dev/null; then
    info "getting instance id from ec2 metadata endpoint"
    instance_id=$(curl --max-time 3 -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
  fi

  if [ -n "$instance_id" ]; then
    # Put logs into a directory for this instance.
    info_system="${collectdir}/${instance_id}"
    # And in a pack that includes the instance id in its name.
    pack_name="collect-${instance_id}"
    mkdir -p "${info_system}"
    echo "$instance_id" > "$info_system"/instance-id.txt
  else
    warning "unable to get instance id"
    return 1
  fi

  ok
}

pack() {
  try "archive gathered log information"

  local tar_bin
  tar_bin="$(command -v tar 2>/dev/null)"
  [ -z "${tar_bin}" ] && warning "TAR archiver not found, please install a TAR archiver to create the collection archive. You can still view the logs in the collect folder."

  cd "$curdir" || { echo "cd failed."; exit 1; }

  ${tar_bin} -cvzf "$curdir/$pack_name".tgz "$collectdir" > /dev/null 2>&1

  ok
}

is_diskfull() {
  try "check disk space usage"

  threshold=70
  i=2
  result=$(df -kh | grep -ve "Filesystem" -ve "loop" | awk '{ print $5 }' | sed 's/%//g')
  exceeded=0

  for percent in ${result}; do
    if [[ "${percent}" -gt "${threshold}" ]]; then
      partition=$(df -kh | head -$i | tail -1| awk '{print $1}')
      echo
      warning "${partition} is ${percent}% full, please ensure adequate disk space to collect and store the log files."
      : $((exceeded++))
    fi
    i=$((i+1))
  done

  if [ "$exceeded" -gt 0 ]; then
    return 1
  else
    ok
  fi
}

get_mounts_info() {
  try "get mount points and volume information"

  mkdir -p "$info_system"
  mount > "$info_system"/mounts.txt
  echo "" >> "$info_system"/mounts.txt
  df -h >> "$info_system"/mounts.txt

  if command -v lvdisplay > /dev/null; then
    lvdisplay > "$info_system"/lvdisplay.txt
    vgdisplay > "$info_system"/vgdisplay.txt
    pvdisplay > "$info_system"/pvdisplay.txt
  fi

  ok
}

get_selinux_info() {
  try "check SELinux status"

  enforced="$(getenforce 2>/dev/null)"

  { [ "${pkgtype}" != "rpm" ] || [ -z "${enforced}" ]; } \
    && info "not installed" \
    && return

  mkdir -p "$info_system"
  echo -e "SELinux mode:\\n    ${enforced}" >  "$info_system"/selinux.txt

  ok
}

get_iptables_info() {
  try "get iptables list"

  mkdir -p "$info_system"
  iptables -nvL -t filter > "$info_system"/iptables-filter.txt
  iptables -nvL -t nat  > "$info_system"/iptables-nat.txt

  ok
}

get_open_files() {
  try "get open files list"

  mkdir -p "$info_system"
  for d in /proc/*/fd; do echo "$d"; find "$d" -maxdepth 1 | wc -l; done > "$info_system"/open-file-counts.txt
  ls -l /proc/*/fd > "$info_system"/open-file-details.txt

  ok
}

get_common_logs() {
  try "collect common operating system logs"

  dstdir="${info_system}/var_log"
  mkdir -p "$dstdir"

  for entry in syslog messages; do
    [ -e "/var/log/${entry}" ] && cp -f /var/log/${entry} "$dstdir"/
  done

  ok
}

get_kernel_logs() {
  try "collect kernel logs"

  dstdir="${info_system}/kernel"
  mkdir -p "$dstdir"
  if [ -e "/var/log/dmesg" ]; then
    cp -f /var/log/dmesg "$dstdir/dmesg.boot"
  fi
  dmesg > "$dstdir/dmesg.current"
  dmesg --ctime > "$dstdir/dmesg.human.current"
  ok
}

get_docker_logs() {
  try "collect Docker and containerd daemon logs"

  dstdir="${info_system}/docker_log"
  mkdir -p "$dstdir"
  case "${init_type}" in
    systemd)
      journalctl -u docker > "${dstdir}"/docker
      journalctl -u containerd > "${info_system}"/containerd.log
      ;;
    other)
      for entry in docker upstart/docker; do
        if [[ -e "/var/log/${entry}" ]]; then
          cp -f /var/log/"${entry}" "${dstdir}"/docker
        fi
      done
      ;;
    *)
      warning "the current operating system is not supported."
      return 1
      ;;
  esac

  ok
}

get_ecs_agent_logs() {
  try "collect Amazon ECS Container Agent logs"

  dstdir="${info_system}/ecs_agent_logs"

  if [ ! -d /var/log/ecs ]; then
    failed "ECS log directory does not exist"
    return 1
  fi

  mkdir -p "$dstdir"

  cp -f /var/log/ecs/* "$dstdir"/

  ok
}

get_pkglist() {
  try "detect installed packages"

  mkdir -p "$info_system"
  case "${pkgtype}" in
    rpm)
      rpm -qa >"$info_system"/pkglist.txt 2>&1
      ;;
    dpkg)
      dpkg --list > "$info_system"/pkglist.txt 2>&1
      ;;
    *)
      warning "unknown package type."
      return 1
      ;;
  esac

  ok
}

get_system_services() {
  try "detect active system services list"

  mkdir -p "$info_system"
  case "${init_type}" in
    systemd)
      systemctl list-units > "$info_system"/services.txt 2>&1
      ;;
    other)
      service --status-all >> "$info_system"/services.txt 2>&1
      ;;
    *)
      warning "unable to determine active services."
      return 1
      ;;
  esac

  top -b -n 1 > "$info_system"/top.txt 2>&1
  ps fauxwww > "$info_system"/ps.txt 2>&1
  netstat -plant > "$info_system"/netstat.txt 2>&1

  ok
}

get_docker_info() {
  try "gather Docker daemon information"

  mkdir -p "$info_system"/docker

  if pgrep dockerd > /dev/null ; then

    timeout 20 docker info > "$info_system"/docker/docker-info.txt 2>&1 || echo "Timed out, ignoring \"docker info output \" "
    timeout 20 docker ps --all --no-trunc > "$info_system"/docker/docker-ps.txt 2>&1 || echo "Timed out, ignoring \"docker ps --all --no-trunc output \" "
    timeout 20 docker images > "$info_system"/docker/docker-images.txt 2>&1 || echo "Timed out, ignoring \"docker images output \" "
    timeout 20 docker version > "$info_system"/docker/docker-version.txt 2>&1 || echo "Timed out, ignoring \"docker version output \" "
    timeout 60 docker stats --all --no-trunc --no-stream > "$info_system"/docker/docker-stats.txt 2>&1 || echo "Timed out, ignoring \"docker stats\" output"

    ok
  else
    warning "the Docker daemon is not running." | tee "$info_system"/docker/docker-not-running.txt
  fi
}

get_ecs_agent_info() {
  try "collect Amazon ECS Container Agent state and config"

  mkdir -p "$info_system"/ecs-agent
  if [ -e /var/lib/ecs/data/ecs_agent_data.json ]; then
    python -mjson.tool < /var/lib/ecs/data/ecs_agent_data.json > "$info_system"/ecs-agent/ecs_agent_data.txt 2>&1
  fi

  if [ -e /var/lib/ecs/data/agent.db ]; then
    cp -f /var/lib/ecs/data/agent.db "$info_system"/ecs-agent/agent.db 2>&1
    chmod +r "$info_system"/ecs-agent/agent.db
  fi

  if [ -e /etc/ecs/ecs.config ]; then
    cp -f /etc/ecs/ecs.config "$info_system"/ecs-agent/ 2>&1
    if grep --quiet "ECS_ENGINE_AUTH_DATA" "$info_system"/ecs-agent/ecs.config; then
      sed -i 's/ECS_ENGINE_AUTH_DATA=.*/ECS_ENGINE_AUTH_DATA=/g' "$info_system"/ecs-agent/ecs.config
    fi
  fi
  ok

  try "collect Amazon ECS Container Agent engine data"

  if pgrep agent > /dev/null ; then
    if command -v curl >/dev/null; then
      if curl --max-time 3 -s http://localhost:51678/v1/tasks | python -mjson.tool > "$info_system"/ecs-agent/agent-running-info.txt 2>&1; then
          ok
      else
          warning "failed to get agent data"
      fi
    else
      warning "curl is unavailable for probing ECS Container Agent introspection endpoint"
    fi
  else
    warning "The Amazon ECS Container Agent is not running" | tee "$info_system"/ecs-agent/ecs-agent-not-running.txt
    return 1
  fi
}

get_docker_containers_info() {
  try "inspect all Docker containers"

  mkdir -p "$info_system"/docker

  if pgrep dockerd > /dev/null ; then
    for i in $(docker ps -a -q); do
      timeout 10 docker inspect "$i" > "$info_system"/docker/container-"$i".txt 2>&1
      if [ $? -eq 124 ]; then
        touch "$info_system"/docker/container-inspect-timed-out.txt
        failed "'docker inspect' timed out, not gathering containers"
        return 1
      fi

      if grep --quiet "ECS_ENGINE_AUTH_DATA" "$info_system"/docker/container-"$i".txt; then
        sed -i 's/ECS_ENGINE_AUTH_DATA=.*/ECS_ENGINE_AUTH_DATA=/g' "$info_system"/docker/container-"$i".txt
      fi
    done
  else
    warning "the Docker daemon is not running." | tee "$info_system"/docker/docker-not-running.txt
    return 1
  fi
  ok
}

get_docker_sysconfig() {
  try "collect Docker sysconfig"

  if [ -e /etc/sysconfig/docker ]; then
    mkdir -p "${info_system}"/docker
    cp /etc/sysconfig/docker "${info_system}"/docker/sysconfig-docker
    ok
  else
    info "/etc/sysconfig/docker not found"
  fi

 try "collect Docker storage sysconfig"

  if [ -e /etc/sysconfig/docker-storage ]; then
    mkdir -p "${info_system}"/docker
    cp /etc/sysconfig/docker-storage "${info_system}"/docker/sysconfig-docker-storage
    ok
  else
    info "/etc/sysconfig/docker-storage not found"
  fi
}


get_docker_daemon_json(){
  try "collect Docker daemon.json"

  if [ -e /etc/docker/daemon.json ]; then
    mkdir -p "${info_system}"/docker
    cp /etc/docker/daemon.json "${info_system}"/docker/daemon.json
    ok
  else
    info "/etc/docker/daemon.json not found"
  fi
}

get_docker_systemd_config(){

  if [[ "$init_type" != "systemd" ]]; then
    return 0
  fi

  try "collect Docker systemd unit file"

  mkdir -p "${info_system}"/docker
  if systemctl cat docker.service > "${info_system}"/docker/docker.service 2>/dev/null; then
   ok
  else
    rm -f "$info_system/docker/docker.service"
    warning "docker.service not found"
  fi

  try "collect containerd systemd unit file"
  if systemctl cat containerd.service > "${info_system}"/docker/containerd.service 2>/dev/null; then
   ok
  else
    rm -f "$info_system/docker/containerd.service"
    warning "containerd.service not found"
  fi
}

get_os_release(){
  try "collect /etc/os-release"

  if [ -f /etc/os-release ]; then
    cat /etc/os-release > "${info_system}"/os-release
    ok
  else
    info "/etc/os-release not found"
  fi
}

enable_docker_debug() {
  try "enable debug mode for the Docker daemon"

  if [ -e /etc/sysconfig/docker ] && grep -q "^\\s*OPTIONS=\"-D" /etc/sysconfig/docker; then
    info "Debug mode is already enabled."
  else

    if [ -e /etc/sysconfig/docker ]; then
      case "${init_type}" in
        systemd)
          sed -i 's/^OPTIONS="\(.*\)/OPTIONS="-D \1/g' /etc/sysconfig/docker
          ok

          try "restart Docker daemon to enable debug mode"
          systemctl restart docker.service
          ok
          ;;
        *)
          echo "OPTIONS=\"-D \$OPTIONS\"" >> /etc/sysconfig/docker

          try "restart Docker daemon to enable debug mode"
          service docker restart
          ok

        esac

    else
      warning "the current operating system is not supported."
    fi
  fi
}

enable_ecs_agent_debug() {
  try "enable debug mode for the Amazon ECS Container Agent"

  if [ -e /etc/ecs/ecs.config ] &&  grep -q "^\\s*ECS_LOGLEVEL=debug" /etc/ecs/ecs.config; then
    info "Debug mode is already enabled."
  else

    case "${init_type}" in
    systemd)
      if [ ! -d /etc/ecs ]; then
        mkdir /etc/ecs
      fi

      echo "ECS_LOGLEVEL=debug" >> /etc/ecs/ecs.config
      ok

      try "restart the Amazon ECS Container Agent to enable debug mode"
      systemctl restart ecs
      ok
      ;;
    *)
      if rpm -q --quiet ecs-init; then
        if [ ! -d /etc/ecs ]; then
          mkdir /etc/ecs
        fi

        echo "ECS_LOGLEVEL=debug" >> /etc/ecs/ecs.config
        ok

        try "restart the Amazon ECS Container Agent to enable debug mode"
        stop ecs; start ecs
        ok
      else
        warning "the current operating system is not supported."
      fi
      ;;
    esac
  fi
}

# --------------------------------------------------------------------------------------------

parse_options "$@"

case "${mode}" in
  brief)
    cleanup
    collect_brief
    pack
    ;;
  enable-debug)
    enable_debug
    ;;
  *)
    help && exit 1
    ;;
esac
