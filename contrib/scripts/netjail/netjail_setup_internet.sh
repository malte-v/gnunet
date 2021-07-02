#!/bin/sh
. "./netjail_core.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LOCAL_M=$1
GLOBAL_N=$2

shift 2

netjail_check $(($LOCAL_M * $GLOBAL_N))

# Starts optionally an amount of nodes without NAT starting with "92.68.151.1"
KNOWN=$(netjail_opt '--known' $@)
KNOWN_NUM=$(netjail_opts '--known' 0 $@)

# Starts optionally 'stunserver' on "92.68.150.254":
STUN=$(netjail_opt '--stun' $@)

if [ $KNOWN -gt 0 ]; then
	shift 2

	KNOWN=$KNOWN_NUM
	
	netjail_check $(($LOCAL_M * $GLOBAL_N + $KNOWN))
fi

if [ $STUN -gt 0 ]; then
	netjail_check_bin stunserver
	
	shift 1
	
	STUN_NODE=$(netjail_print_name "S" 254)
fi

netjail_check_bin $1

LOCAL_GROUP="192.168.15"
GLOBAL_GROUP="92.68.150"
KNOWN_GROUP="92.68.151"

CLEANUP=0
echo "Start [local: $LOCAL_GROUP.0/24, global: $GLOBAL_GROUP.0/16, stun: $STUN]"

NETWORK_NET=$(netjail_print_name "n" $GLOBAL_N $LOCAL_M)

netjail_bridge $NETWORK_NET

for X in $(seq $KNOWN); do
	KNOWN_NODE=$(netjail_print_name "K" $X)

	netjail_node $KNOWN_NODE
	netjail_node_link_bridge $KNOWN_NODE $NETWORK_NET "$KNOWN_GROUP.$X" 16
done

for N in $(seq $GLOBAL_N); do
	ROUTER=$(netjail_print_name "R" $N)

	netjail_node $ROUTER 
	netjail_node_link_bridge $ROUTER $NETWORK_NET "$GLOBAL_GROUP.$N" 16

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

WAITING=""
KILLING=""

if [ $STUN -gt 0 ]; then
	netjail_node $STUN_NODE
	netjail_node_link_bridge $STUN_NODE $NETWORK_NET "$GLOBAL_GROUP.254" 16

	netjail_node_exec $STUN_NODE 0 1 stunserver &
	KILLING="$!"
fi

for X in $(seq $KNOWN); do
	KNOWN_NODE=$(netjail_print_name "K" $X)
	INDEX=$(($X - 1))
	
	FD_X=$(($INDEX * 2 + 3 + 0))
	FD_Y=$(($INDEX * 2 + 3 + 1))

	netjail_node_exec $KNOWN_NODE $FD_X $FD_Y $@ &
	WAITING="$! $WAITING"
done

for N in $(seq $GLOBAL_N); do
	for M in $(seq $LOCAL_M); do
		NODE=$(netjail_print_name "N" $N $M)
		INDEX=$(($LOCAL_M * ($N - 1) + $M - 1 + $KNOWN))

		FD_X=$(($INDEX * 2 + 3 + 0))
		FD_Y=$(($INDEX * 2 + 3 + 1))

		netjail_node_exec $NODE $FD_X $FD_Y $@ &
		WAITING="$! $WAITING"
	done
done

cleanup() {
	if [ $STUN -gt 0 ]; then
		STUN_NODE=$(netjail_print_name "S" 254)

		netjail_node_unlink_bridge $STUN_NODE $NETWORK_NET
		netjail_node_clear $STUN_NODE
	fi

	for X in $(seq $KNOWN); do
		KNOWN_NODE=$(netjail_print_name "K" $X)
		
		netjail_node_unlink_bridge $KNOWN_NODE $NETWORK_NET
		netjail_node_clear $KNOWN_NODE
	done

	for N in $(seq $GLOBAL_N); do
		ROUTER_NET=$(netjail_print_name "r" $N)

		for M in $(seq $LOCAL_M); do
			NODE=$(netjail_print_name "N" $N $M)

			netjail_node_unlink_bridge $NODE $ROUTER_NET
			netjail_node_clear $NODE
		done

		ROUTER=$(netjail_print_name "R" $N)
		
		netjail_bridge_clear $ROUTER_NET
		netjail_node_unlink_bridge $ROUTER $NETWORK_NET
		netjail_node_clear $ROUTER
	done

	netjail_bridge_clear $NETWORK_NET
}

trapped_cleanup() {
	netjail_killall $WAITING
	netjail_killall $KILLING

	cleanup
}

trap 'trapped_cleanup' 2

netjail_waitall $WAITING
netjail_killall $KILLING
wait

cleanup

echo "Done"
