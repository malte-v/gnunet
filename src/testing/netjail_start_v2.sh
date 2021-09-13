#!/bin/bash
. "./../testing/netjail_core_v2.sh"
. "./../testing/topo.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

filename=$1
PREFIX=$2

read_topology $filename

shift 2

LOCAL_GROUP="192.168.15"
GLOBAL_GROUP="92.68.150"
KNOWN_GROUP="92.68.151"


echo "Start [local: $LOCAL_GROUP.0/24, global: $GLOBAL_GROUP.0/16]"

netjail_bridge
NETWORK_NET=$RESULT

for X in $(seq $KNOWN); do
	netjail_node
	KNOWN_NODES[$X]=$RESULT
	netjail_node_link_bridge ${KNOWN_NODES[$X]} $NETWORK_NET "$KNOWN_GROUP.$X" 16
	KNOWN_LINKS[$X]=$RESULT
done

declare -A NODES
declare -A NODE_LINKS

for N in $(seq $GLOBAL_N); do
	netjail_node
	ROUTERS[$N]=$RESULT
	netjail_node_link_bridge ${ROUTERS[$N]} $NETWORK_NET "$GLOBAL_GROUP.$N" 16
	NETWORK_LINKS[$N]=$RESULT
	netjail_bridge
	ROUTER_NETS[$N]=$RESULT
	
	for M in $(seq $LOCAL_M); do
		netjail_node
		NODES[$N,$M]=$RESULT
		netjail_node_link_bridge ${NODES[$N,$M]} ${ROUTER_NETS[$N]} "$LOCAL_GROUP.$M" 24
		NODE_LINKS[$N,$M]=$RESULT
	done

	ROUTER_ADDR="$LOCAL_GROUP.$(($LOCAL_M+1))"
	netjail_node_link_bridge ${ROUTERS[$N]} ${ROUTER_NETS[$N]} $ROUTER_ADDR 24
	ROUTER_LINKS[$N]=$RESULT
	
	netjail_node_add_nat ${ROUTERS[$N]} $ROUTER_ADDR 24
	
	for M in $(seq $LOCAL_M); do
		netjail_node_add_default ${NODES[$N,$M]} $ROUTER_ADDR
	done
done
