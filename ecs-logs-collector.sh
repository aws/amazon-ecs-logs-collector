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
collectdir="${curdir}/collect"
# infodir is the directory used to collate each check's data, this may
# be updated prior to checks to place this under a more unique path,
# such as "$collectdir/i-ffffffffffffffffff" to allow for distinction
# of unpacked logs.
infodir="$collectdir"
# pack_name is the name of the resulting tarball. This will generally
# be collect-i-ffffffffffffffffff, where i-ffffffffffffffffff is the
# instance id.
pack_name="collect"

# Shared check variables

# info_system is where the checks' data is placed.
info_system="${infodir}/system"
# pkgtype is the detected packaging system used on the host (eg: yum, deb)
pkgtype=''  # defined in get_sysinfo
# os_name is the machine name used for casing check behavior.
os_name=''  # defined in get_sysinfo
progname='' # defined in parse_options

# Script run defaults

mode='brief' # defined in parse_options


# Common functions
# ---------------------------------------------------------------------------------------

help() {
  echo "USAGE: ${progname} [--mode=[brief|debug]]"
  echo "       ${progname} --help"
  echo ""
  echo "OPTIONS:"
  echo "     --mode  Sets the desired mode of the script. For more information,"
  echo "             see the MODES section."
  echo "     --help  Show this help message."
  echo ""
  echo "MODES:"
  echo "     brief       Gathers basic operating system, Docker daemon, and Amazon"
  echo "                 ECS Container Agent logs. This is the default mode."
  echo "     debug       Collects 'brief' logs and also enables debug mode for the"
  echo "                 Docker daemon and the Amazon ECS Container Agent."
  echo "     debug-only  Enables debug mode for the Docker daemon and the Amazon"
  echo "                 ECS Container Agent without collecting logs"

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
        echo "Command not found: '--$param'"
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

fail() {
  echo "failed"
}

failed() {
  local reason=$*
  echo "failed: $reason"
}

die() {
  echo "ERROR: $* .. exiting..."
  exit 1
}

is_root() {
  try "check if the script is running as root"

  if [[ "$(id -u)" != "0" ]]; then
    die "This script must be run as root!"

  fi

  ok
}

is_diskfull() {
  try "check disk space usage"

  threshold=70
  i=2
  result=$(df -kh |grep -v "Filesystem" | awk '{ print $5 }' | sed 's/%//g')
  exceeded=0

  for percent in ${result}; do
    if [[ "${percent}" -gt "${threshold}" ]]; then
      partition=$(df -kh | head -$i | tail -1| awk '{print $1}')
      echo
      warning "${partition} is ${percent}% full, please ensure adequate disk space to collect and store the log files."
      : $((exceeded++))
    fi
    let i=$i+1
  done

  if [ "$exceeded" -gt 0 ]; then
    return 1
  else
    ok
  fi
}

cleanup() {
  rm -rf "$infodir" >/dev/null 2>&1
  rm -f "$curdir"/collect.tgz
}

init() {
  is_root
  try_set_instance_infodir
  get_sysinfo
}

# change_infodir updates the collection location for the script.
#
# This should not be used after updating the location as check data
# would be spread across unknown locations.
change_infodir() {
  local newdir="$1"
  infodir="$newdir"
  info_system="$newdir"
}

try_set_instance_infodir() {
  try "resolve instance-id"

  if command -v curl > /dev/null; then
    instance_id=$(curl --max-time 3 -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
    if [[ -n "$instance_id" ]]; then
      # Put logs into a directory for this instance.
      change_infodir "${collectdir}/${instance_id}"
      # And in a pack that includes the instance id in its name.
      pack_name="collect-${instance_id}"
      mkdir -p "${info_system}"
      echo "$instance_id" > "$info_system"/instance-id.txt
    else
      warning "unable to resolve instance metadata"
      return 1
    fi
  else
    warning "curl is unavailable for querying"
    return 1
  fi

  ok
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
  get_ecs_agent_logs
  get_ecs_agent_info
  get_ecs_init_logs
}

enable_debug() {
  init
  enable_docker_debug
  enable_ecs_agent_debug
}

pack() {
  try "archive gathered log information"

  local tar_bin
  tar_bin="$(command -v tar 2>/dev/null)"
  [ -z "${tar_bin}" ] && warning "TAR archiver not found, please install a TAR archiver to create the collection archive. You can still view the logs in the collect folder."

  cd "$curdir" || { echo "cd failed."; exit 1; }

  ${tar_bin} -cvzf "$collectdir/../$pack_name".tgz "$infodir" > /dev/null 2>&1

  ok
}

# Routines
# ---------------------------------------------------------------------------------------
get_sysinfo() {
  try "collect system information"

  res="$(/bin/uname -m)"
  ( [ "${res}" = "amd64" ] || [ "$res" = "x86_64" ] ) && arch="x86_64" || arch="i386"

  found_file=""
  for f in system-release redhat-release lsb-release debian_version; do
    [ -f "/etc/${f}" ] && found_file="${f}" && break
  done

  case "${found_file}" in
    system-release)
      pkgtype="rpm"
      if grep --quiet "Amazon Linux AMI release" /etc/${found_file}; then
        os_name="amazon"
      elif grep --quiet "Amazon Linux 2" /etc/${found_file}; then
        os_name="amazon2"
      elif grep --quiet "Red Hat" /etc/${found_file}; then
        os_name="redhat"
      elif grep --quiet "CentOS" /etc/${found_file}; then
        os_name="redhat"
      fi
      ;;
    debian_version)
      pkgtype="deb"
      if grep --quiet "8" /etc/${found_file}; then
        os_name="debian"
      fi
      ;;
    lsb-release)
      pkgtype="deb"
      if grep --quiet "Ubuntu 14.04" /etc/${found_file}; then
        os_name="ubuntu14"
      fi
      ;;
    *)
      fail
      die "Unsupported OS detected."
      ;;
  esac

  ok
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

  ( [ "${pkgtype}" != "rpm" ] || [ -z "${enforced}" ] ) \
    && info "not installed" \
    && return

  mkdir -p "$info_system"
  echo -e "SELinux mode:\n    ${enforced}" >  "$info_system"/selinux.txt

  ok
}

get_iptables_info() {
  try "get iptables list"

  mkdir -p "$info_system"
  /sbin/iptables -nvL -t filter > "$info_system"/iptables-filter.txt
  /sbin/iptables -nvL -t nat  > "$info_system"/iptables-nat.txt

  ok
}

get_common_logs() {
  try "collect common operating system logs"
  dstdir="${info_system}/var_log"
  mkdir -p "$dstdir"

  for entry in syslog messages; do
    [ -e "/var/log/${entry}" ] && cp -fR /var/log/${entry} "$dstdir"/
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
  try "collect Docker daemon logs"
  dstdir="${info_system}/docker_log"
  mkdir -p "$dstdir"
  case "${os_name}" in
    amazon)
      cp /var/log/docker "$dstdir"
      ;;
    amazon2)
      if [ -e /bin/journalctl ]; then
        /bin/journalctl -u docker > ${dstdir}/docker
      fi
      ;;
    redhat)
      if [ -e /bin/journalctl ]; then
        /bin/journalctl -u docker > "$dstdir"/docker
      fi
      ;;
    debian)
      if [ -e /bin/journalctl ]; then
        /bin/journalctl -u docker > "$dstdir"/docker
      fi
      ;;
    ubuntu14)
      cp -f /var/log/upstart/docker* "${dstdir}"
      ;;
    *)
      warning "The current operating system is not supported."
      return 1
      ;;
  esac

  ok
}

get_ecs_agent_logs() {
  try "collect Amazon ECS Container Agent logs"
  dstdir="${info_system}/ecs-agent"

  if [ ! -d /var/log/ecs ]; then
    failed "ECS log directory does not exist"
    return 1
  fi

  mkdir -p "$dstdir"
  for agent_log_file in /var/log/ecs/ecs-agent.log*; do
    cp -fR "$agent_log_file" "$dstdir"/
  done

  ok
}

get_ecs_init_logs() {
  try "collect Amazon ECS init logs"
  dstdir="${info_system}/ecs-init"

  if [ ! -d /var/log/ecs ]; then
    failed "ECS log directory does not exist"
    return 1
  fi

  mkdir -p "$dstdir"
  for ecs_init_log_file in /var/log/ecs/ecs-init.log*; do
    cp -fR "$ecs_init_log_file" "$dstdir"/
  done

  ok
}

get_pkglist() {
  try "detect installed packages"

  mkdir -p "$info_system"
  case "${pkgtype}" in
    rpm)
      rpm -qa >"$info_system"/pkglist.txt 2>&1
      ;;
    deb)
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
  case "${os_name}" in
    amazon)
      chkconfig --list > "$info_system"/services.txt 2>&1
      ;;
    amazon2)
      systemctl list-units > ${info_system}/services.txt 2>&1
      ;;
    redhat)
      /bin/systemctl list-units > "$info_system"/services.txt 2>&1
      ;;
    debian)
      /bin/systemctl list-units > "$info_system"/services.txt 2>&1
      ;;
    ubuntu14)
      /sbin/initctl list | awk '{ print $1 }' | xargs -n1 initctl show-config > "$info_system"/services.txt 2>&1
      printf "\n\n\n\n" >> "$info_system"/services.txt 2>&1
      /usr/bin/service --status-all >> "$info_system"/services.txt 2>&1
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

  if pgrep dockerd > /dev/null ; then
    mkdir -p "$info_system"/docker

    timeout 20 docker info > "$info_system"/docker/docker-info.txt 2>&1 || echo "Timed out, ignoring \"docker info output \" "
    timeout 20 docker ps --all --no-trunc > "$info_system"/docker/docker-ps.txt 2>&1 || echo "Timed out, ignoring \"docker ps --all --no-truc output \" "
    timeout 20 docker images > "$info_system"/docker/docker-images.txt 2>&1 || echo "Timed out, ignoring \"docker images output \" "
    timeout 20 docker version > "$info_system"/docker/docker-version.txt 2>&1 || echo "Timed out, ignoring \"docker version output \" "

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

enable_docker_debug() {
  try "enable debug mode for the Docker daemon"

  case "${os_name}" in
    amazon)

      if [ -e /etc/sysconfig/docker ] && grep -q "^\s*OPTIONS=\"-D" /etc/sysconfig/docker
      then
        info "Debug mode is already enabled."
      else

        if [ -e /etc/sysconfig/docker ]; then
          echo "OPTIONS=\"-D \$OPTIONS\"" >> /etc/sysconfig/docker

          try "restart Docker daemon to enable debug mode"
          /sbin/service docker restart
        fi

        ok

      fi
      ;;
    amazon2)

      if [ -e /etc/sysconfig/docker ] && grep -q "^\s*OPTIONS=\"-D" /etc/sysconfig/docker
      then
        info "Debug mode is already enabled."
      else

        if [ -e /etc/sysconfig/docker ]; then
          sed -i 's/^OPTIONS="\(.*\)/OPTIONS="-D \1/g' /etc/sysconfig/docker

          try "restart Docker daemon to enable debug mode"
          systemctl restart docker.service
        fi

        ok

      fi
      ;;
    *)
      warning "the current operating system is not supported."
      ;;
  esac
}

enable_ecs_agent_debug() {
  try "enable debug mode for the Amazon ECS Container Agent"

  case "${os_name}" in
    amazon)

      if [ -e /etc/ecs/ecs.config ] &&  grep -q "^\s*ECS_LOGLEVEL=debug" /etc/ecs/ecs.config
      then
        info "Debug mode is already enabled."
      else
        echo "ECS_LOGLEVEL=debug" >> /etc/ecs/ecs.config

        try "restart the Amazon ECS Container Agent to enable debug mode"
        stop ecs; start ecs
        ok

      fi
      ;;
    amazon2)

      if [ -e /etc/ecs/ecs.config ] &&  grep -q "^\s*ECS_LOGLEVEL=debug" /etc/ecs/ecs.config
      then
        info "Debug mode is already enabled."
      else
        echo "ECS_LOGLEVEL=debug" >> /etc/ecs/ecs.config

        try "restart the Amazon ECS Container Agent to enable debug mode"
        systemctl restart ecs
        ok

      fi
      ;;
    *)
      warning "the current operating system is not supported."
      ;;
  esac
}

# --------------------------------------------------------------------------------------------

parse_options "$@"

case "${mode}" in
  brief)
    cleanup
    collect_brief
    pack
    ;;
  debug)
    cleanup
    collect_brief
    enable_debug
    pack
    ;;
  debug-only)
    enable_debug
    ;;
  *)
    help && exit 1
    ;;
esac
