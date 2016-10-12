#!/bin/bash
#
# Copyright 2016 Amazon.com, Inc. or its affiliates.
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
# - Collects Docker daemon and Amazon ECS container agent logs on Amazon Linux,
#   Redhat 7, Debian 8.
# - Collects general operating system logs.
# - Optional ability to enable debug mode for the Docker daemon and Amazon ECS
#   container agent on Amazon Linux variants, such as the Amazon ECS-optimized
#   AMI. For usage information, see --help.

export LANG="C"
export LC_ALL="C"

# Common options
curdir="$(dirname $0)"
infodir="${curdir}/collect"
info_system="${infodir}/system"

# Global options
pkgtype=''  # defined in get_sysinfo
os_name=''  # defined in get_sysinfo
progname='' # defined in parse_options


# Common functions
# ---------------------------------------------------------------------------------------

help()
{
  echo "USAGE: ${progname} [--mode=[brief|debug]]"
  echo "       ${progname} --help"
  echo ""
  echo "OPTIONS:"
  echo "     --mode  Sets the desired mode of the script. For more information,"
  echo "             see the MODES section."
  echo "     --help  Show this help message."
  echo ""
  echo "MODES:"
  echo "     brief   Gathers basic operating system, Docker daemon, and Amazon"
  echo "             ECS container agent logs. This is the default mode."
  echo "     debug   Collects 'brief' logs and also enables debug mode for the"
  echo "             Docker daemon and the Amazon ECS container agent."
}

parse_options()
{
  local count="$#"

  progname="$0"

  for i in `seq ${count}`; do
    eval arg=\$$i
    param="`echo ${arg} | awk -F '=' '{print $1}' | sed -e 's|--||'`"
    val="`echo ${arg} | awk -F '=' '{print $2}'`"

    case "${param}" in
      mode)
        eval $param="${val}"
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

ok()
{
  echo "ok"
}

info()
{
  echo "$*"
}

try()
{
  echo -n "Trying to $*... "
}

warning()
{
  echo "Warning $*.. "
}

fail()
{
  echo "failed"
}

die()
{
  echo "ERROR: $*.. exiting..."
  exit 1
}

is_root()
{
  try "Checking if script is running as root..."

  if [[ "$(id -u)" != "0" ]]; then
    die "This script must be run as root!"

  fi

  ok
}

is_diskfull()
{
  try "Checking disk space usage..."

  threshold=70
  i=2
  result=`df -kh |grep -v "Filesystem" | awk '{ print $5 }' | sed 's/%//g'`

  for percent in ${result}; do
    if [[ "${percent}" -gt "${threshold}" ]]; then
      partition=`df -kh | head -$i | tail -1| awk '{print $1}'`
      warning "${partition} is ${percent}% full, please ensure adequate disk space to collect and store the log files."
    fi
    let i=$i+1
  done

  ok
}

cleanup()
{
  rm -rf ${infodir} >/dev/null 2>&1
  rm -f ${curdir}/collect.tgz
}

collect_brief() {
  is_root
  is_diskfull
  get_sysinfo
  get_common_logs
  get_mounts_info
  get_selinux_info
  get_iptables_info
  get_pkglist
  get_system_services
  get_docker_info
  get_ecs_logs
  get_containers_info
  get_docker_logs
}

collect_debug() {
  collect_brief
  enable_docker_debug
  enable_ecs_agent_debug
}

pack()
{
  try "Archiving gathered log information..."

  local tar_bin
  tar_bin="`which tar 2>/dev/null`"
  [ -z "${tar_bin}" ] && warning "TAR archiver not found, please install a TAR archiver to create the collection archive. You can still view the logs in the collect folder."

  cd ${curdir}
  ${tar_bin} -czf ${infodir}.tgz ${infodir} > /dev/null 2>&1

  ok
}

# Routines
# ---------------------------------------------------------------------------------------

get_sysinfo()
{
  try "Collecting system information..."

  res="`/bin/uname -m`"
  [ "${res}" = "amd64" -o "$res" = "x86_64" ] && arch="x86_64" || arch="i386"

  found_file=""
  for f in system-release redhat-release lsb-release debian_version; do
    [ -f "/etc/${f}" ] && found_file="${f}" && break
  done

  case "${found_file}" in
    system-release)
      pkgtype="rpm"
      if grep "Amazon" /etc/${found_file}; then
        os_name="amazon"
      elif grep "Red Hat" /etc/${found_file}; then
        os_name="redhat"
      fi
      ;;
    debian_version)
      pkgtype="deb"
      if grep "8" /etc/${found_file}; then
        os_name="debian"
      fi
      ;;
    *)
      fail
      die "Unsupported OS detected."
      ;;
  esac

  ok
}

get_mounts_info()
{
  try "Getting mount points and volume information..."
  mkdir -p ${info_system}
  mount > ${info_system}/mounts.txt
  echo "" >> ${info_system}/mounts.txt
  df -h >> ${info_system}/mounts.txt

  if [ -e /sbin/lvs ]; then
    lvs > ${info_system}/lvs.txt
    pvs > ${info_system}/pvs.txt
    vgs > ${info_system}/vgs.txt
  fi

  ok
}

get_selinux_info()
{
  try "Checking SELinux status..."

  enforced="`getenforce 2>/dev/null`"

  [ "${pkgtype}" != "rpm" -o -z "${enforced}" ] \
        && info "not installed" \
        && return

  mkdir -p ${info_system}
  echo -e "SELinux mode:\n    ${enforced}" >  ${info_system}/selinux.txt

  ok
}

get_iptables_info()
{
  try "Getting iptables list..."

  mkdir -p ${info_system}
  /sbin/iptables -nvL -t nat  > ${info_system}/iptables.txt

  ok
}

get_common_logs()
{
  try "Collecting common operating system logs..."
  dstdir="${info_system}/var_log"
  mkdir -p ${dstdir}

  for entry in syslog messages dmesg; do
    [ -e "/var/log/${entry}" ] && cp -fR /var/log/${entry} ${dstdir}/
  done

  ok
}

get_docker_logs()
{
  try "Collecting Docker daemon logs..."
  dstdir="${info_system}/docker_log"
  mkdir -p ${dstdir}
  case "${os_name}" in
    amazon)
      cp /var/log/docker ${dstdir}
      ;;
    redhat)
      if [ -e /bin/journalctl ]; then
        /bin/journalctl -u docker > ${dstdir}/docker
      fi
      ;;
    debian)
      if [ -e /bin/journalctl ]; then
        /bin/journalctl -u docker > ${dstdir}/docker
      fi
      ;;
    *)
      warning "The current operating system is not supported."
      ;;
  esac

}

get_ecs_logs()
{
  try "Collecting Amazon ECS container agent logs..."
  dstdir="${info_system}/ecs-agent"

  mkdir -p ${dstdir}
  for entry in ecs-agent.log*; do
    cp -fR /var/log/ecs/${entry} ${dstdir}/
  done

  ok
}

get_pkglist()
{
  try "Detectng installed packages..."

  mkdir -p ${info_system}
  case "${pkgtype}" in
    rpm)
      rpm -qa >${info_system}/pkglist.txt 2>&1
      ;;
    deb)
      dpkg --list > ${info_system}/pkglist.txt 2>&1
      ;;
    *)
      warning "Unknown package type."
      ;;
  esac

  ok
}

get_system_services()
{
  try "Detecting active system services list..."
  mkdir -p ${info_system}
  case "${os_name}" in
    amazon)
      chkconfig --list > ${info_system}/services.txt 2>&1
      ;;
    redhat)
      /bin/systemctl list-units > ${info_system}/services.txt 2>&1
      ;;
    debian)
      /bin/systemctl list-units > ${info_system}/services.txt 2>&1
      ;;
    *)
      warning "Unable to determine active services."
      ;;
  esac

  top -b -n 1 > ${info_system}/top.txt 2>&1
  ps -fauxwww > ${info_system}/ps.txt 2>&1
  netstat -plant > ${info_system}/netstat.txt 2>&1

  ok
}

get_docker_info()
{
  try "Gathering Docker daemon information..."

  pgrep docker > /dev/null
  if [[ "$?" -eq 0 ]]; then
    mkdir -p ${info_system}/docker

    docker info > ${info_system}/docker/docker-info.txt 2>&1
    docker ps --all --no-trunc > ${info_system}/docker/docker-ps.txt 2>&1
    docker images > ${info_system}/docker/docker-images.txt 2>&1
    docker version > ${info_system}/docker/docker-version.txt 2>&1

    ok

  else
    die "The Docker daemon is not running."
  fi
}

get_containers_info()
{
  try "Inspecting running Docker containers and gathering Amazon ECS container agent data..."
  pgrep agent > /dev/null

  if [[ "$?" -eq 0 ]]; then
    mkdir -p ${info_system}/docker

    for i in `docker ps |awk '{print $1}'|grep -v CONTAINER`;
    do docker inspect $i > $info_system/docker/container-$i.txt 2>&1;
    done

    if [ -e /usr/bin/curl ]; then
      curl -s http://localhost:51678/v1/tasks | python -mjson.tool > ${info_system}/ecs-agent/agent-running-info.txt 2>&1
    fi

    if [ -e /var/lib/ecs/data/ecs_agent_data.json ]; then
      cat  /var/lib/ecs/data/ecs_agent_data.json | python -mjson.tool > ${info_system}/ecs-agent/ecs_agent_data.txt 2>&1
    fi

    if [ -e /etc/ecs/ecs.config ]; then
      cp -f /etc/ecs/ecs.config ${info_system}/ecs-agent/ 2>&1
    fi

    ok

  else
    die "The Amazon ECS container agent is not running."
  fi
}

enable_docker_debug()
{
  try "Enabling debug mode for the Docker daemon."

  case "${os_name}" in
    amazon)

      if [ -e /etc/sysconfig/docker ] && grep -q "OPTIONS=\"-D" /etc/sysconfig/docker
      then
        info "Debug mode is already enabled."
      else

        if [ -e /etc/sysconfig/docker ]; then
          echo "OPTIONS=\"-D\"" >> /etc/sysconfig/docker

          try "Restarting Docker daemon to enable debug mode..."
          /sbin/service docker restart
        fi

        ok

      fi
      ;;
    *)
      warning "The current operating system is not supported."
      ;;
  esac
}

enable_ecs_agent_debug()
{
  try "Enabling debug mode for the Amazon ECS container agent..."

  case "${os_name}" in
    amazon)

      if [ -e /etc/ecs/ecs.config ] &&  grep -q "ECS_LOGLEVEL=debug" /etc/ecs/ecs.config
      then
        info "Debug mode is already enabled."
      else
        if [ -e /etc/ecs/ecs.config ]; then
          echo "ECS_LOGLEVEL=debug" >> /etc/ecs/ecs.config

          try "Restarting the Amazon ECS container agent to enable debug mode."
          stop ecs; start ecs
        fi

        ok

      fi
      ;;
    *)
      warning "The current operating system is not supported."
      ;;
  esac
}

# --------------------------------------------------------------------------------------------

parse_options $*

[ -z "${mode}" ] && mode="brief"

case "${mode}" in
  brief)
    cleanup
    collect_brief
    ;;
  debug)
    cleanup
    collect_debug
    ;;
  *)
    help && exit 1
    ;;
esac

pack
