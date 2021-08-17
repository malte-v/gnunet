#!/bin/sh
. "./../testing/netjail_core.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOCAL_M=$1
GLOBAL_N=$2

# TODO: stunserver? ..and globally known peer?

shift 2

LOCAL_GROUP="192.168.15"
GLOBAL_GROUP="92.68.150"

NETWORK_NET=$(netjail_print_name "n" $GLOBAL_N $LOCAL_M)

netjail_bridge $NETWORK_NET

for N in $(seq $GLOBAL_N); do
	ROUTER=$(netjail_print_name "R" $N)

	netjail_node $ROUTER 
	netjail_node_link_bridge $ROUTER $NETWORK_NET "$GLOBAL_GROUP.$N" 24

	ROUTER_NET=$(netjail_print_name "r" $N)

	netjail_bridge $ROUTER_NET
	
	for M in $(seq $LOCAL_M); do
		NODE=$(netjail_print_name "N" $N $M)

		netjail_node $NODE
		netjail_node_link_bridge $NODE $ROUTER_NET "$LOCAL_GROUP.$M" 24
	done

	ROUTER_ADDR="$LOCAL_GROUP.$(($LOCAL_M+1))"

	netjail_node_link_bridge $ROUTER $ROUTER_NET $ROUTER_ADDR 24
	netjail_node_add_nat $ROUTER $ROUTER_ADDR 24
	
	for M in $(seq $LOCAL_M); do
		NODE=$(netjail_print_name "N" $N $M)
		
		netjail_node_add_default $NODE $ROUTER_ADDR
	done
done


