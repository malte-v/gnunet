#!/bin/sh

. "./netjail_core.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

PREFIX=$PPID
LOCAL_M=$1
GLOBAL_N=$2

shift 2

netjail_check $(($LOCAL_M * $GLOBAL_N))

# Starts optionally an amount of nodes without NAT starting with "92.68.151.1"
netjail_opt '--known' $@
KNOWN=$RESULT
netjail_opts '--known' 0 $@
KNOWN_NUM=$RESULT

# Starts optionally 'stunserver' on "92.68.150.254":
netjail_opt '--stun' $@
STUN=$RESULT

if [ $KNOWN -gt 0 ]; then
	shift 2

	KNOWN=$KNOWN_NUM
	
	netjail_check $(($LOCAL_M * $GLOBAL_N + $KNOWN))
fi

if [ $STUN -gt 0 ]; then
	netjail_check_bin stunserver
	
	shift 1
fi

netjail_check_bin $1

LOCAL_GROUP="192.168.15"
GLOBAL_GROUP="92.68.150"
KNOWN_GROUP="92.68.151"

CLEANUP=0
echo "Start [local: $LOCAL_GROUP.0/24, global: $GLOBAL_GROUP.0/16, stun: $STUN]"

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

WAITING=""
KILLING=""

if [ $STUN -gt 0 ]; then
	netjail_node
	STUN_NODE=$RESULT
	netjail_node_link_bridge $STUN_NODE $NETWORK_NET "$GLOBAL_GROUP.254" 16
	STUN_LINK=$RESULT

	netjail_node_exec $STUN_NODE 0 1 stunserver &
	KILLING="$!"
fi

for X in $(seq $KNOWN); do
	INDEX=$(($X - 1))

	FD_X=$(($INDEX * 2 + 3 + 0))
	FD_Y=$(($INDEX * 2 + 3 + 1))

	netjail_node_exec ${KNOWN_NODES[$X]} $FD_X $FD_Y $@ &
	WAITING="$! $WAITING"
done

for N in $(seq $GLOBAL_N); do
	for M in $(seq $LOCAL_M); do
		INDEX=$(($LOCAL_M * ($N - 1) + $M - 1 + $KNOWN))
		
		FD_X=$(($INDEX * 2 + 3 + 0))
		FD_Y=$(($INDEX * 2 + 3 + 1))

		netjail_node_exec ${NODES[$N,$M]} $FD_X $FD_Y $@ &
		WAITING="$! $WAITING"
	done
done

cleanup() {
	if [ $STUN -gt 0 ]; then
		netjail_node_unlink_bridge $STUN_LINK
		netjail_node_clear $STUN_NODE
	fi

	for X in $(seq $KNOWN); do
		netjail_node_unlink_bridge ${KNOWN_LINKS[$X]}
		netjail_node_clear ${KNOWN_NODES[$X]}
	done

	for N in $(seq $GLOBAL_N); do
		for M in $(seq $LOCAL_M); do
			netjail_node_unlink_bridge ${NODE_LINKS[$N,$M]}
			netjail_node_clear ${NODES[$N,$M]}
		done

		netjail_node_unlink_bridge ${ROUTER_LINKS[$N]}
		netjail_bridge_clear ${ROUTER_NETS[$N]}
		netjail_node_unlink_bridge ${NETWORK_LINKS[$N]}
		netjail_node_clear ${ROUTERS[$N]}
	done

	netjail_bridge_clear $NETWORK_NET
}

trapped_cleanup() {
	netjail_killall $WAITING
	netjail_killall $KILLING

	cleanup
}

trap 'trapped_cleanup' ERR

netjail_waitall $WAITING
netjail_killall $KILLING
wait

cleanup

echo "Done"
