#!/bin/sh
. "./../testing/netjail_core_v2.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

M=$1
N=$2

NODE=$6

netjail_node_exec_without_fds_and_sudo $NODE $3 $4 $5 $1 $2 
