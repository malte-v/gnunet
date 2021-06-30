#!/bin/sh
. "./netjail_core.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOCAL_M=$1
M=$2
N=$3

NODE=$(netjail_print_name "N" $N $M)
INDEX=$(($LOCAL_M * ($N - 1) + $M - 1))

FD_X=$(($INDEX * 2 + 3 + 0))
FD_Y=$(($INDEX * 2 + 3 + 1))

netjail_node_exec_without_fds $NODE $@
