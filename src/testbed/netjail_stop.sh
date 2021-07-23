#!/bin/sh
. "./../testbed/netjail_core.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOCAL_M=$1
GLOBAL_N=$2
NETWORK_NET=$(netjail_print_name "n" $GLOBAL_N $LOCAL_M)

shift 2

for N in $(seq $GLOBAL_N); do
	for M in $(seq $LOCAL_M); do
		netjail_node_clear $(netjail_print_name "N" $N $M)
	done
	
	netjail_bridge_clear $(netjail_print_name "r" $N)
	netjail_node_clear $(netjail_print_name "R" $N)
done

netjail_bridge_clear $NETWORK_NET

echo "Done"
