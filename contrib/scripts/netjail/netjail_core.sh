#!/bin/sh
# 

JAILOR=${SUDO_USER:?must run in sudo}

# running with `sudo` is required to be
# able running the actual commands as the
# original user.

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

netjail_opt() {
	OPT=$1
	shift 1

	INDEX=1

	while [ $# -gt 0 ]; do
		if [ "$1" = "$OPT" ]; then
			printf "%d" $INDEX
			return
		fi

		INDEX=$(($INDEX + 1))
		shift 1
	done

	printf "%d" 0
}

netjail_check() {
	NODE_COUNT=$1

	FD_COUNT=$(($(ls /proc/self/fd | wc -w) - 4))

	# quit if `$FD_COUNT < ($LOCAL_M * $GLOBAL_N * 2)`:
	# the script also requires `sudo -C ($FD_COUNT + 4)`
	# so you need 'Defaults closefrom_override' in the
	# sudoers file.

	if [ $FD_COUNT -lt $(($NODE_COUNT * 2)) ]; then
		echo "File descriptors do not match requirements!" >&2
		exit 1
	fi
}

netjail_print_name() {
	printf "%s%02x%02x" $1 $2 ${3:-0}
}

netjail_bridge() {
	BRIDGE=$1

	ip link add $BRIDGE type bridge
	ip link set dev $BRIDGE up
}

netjail_bridge_clear() {
	BRIDGE=$1

	ip link delete $BRIDGE
}

netjail_node() {
	NODE=$1

	ip netns add $NODE
}

netjail_node_clear() {
	NODE=$1

	ip netns delete $NODE
}

netjail_node_link_bridge() {
	NODE=$1
	BRIDGE=$2
	ADDRESS=$3
	MASK=$4
	
	LINK_IF="$NODE-$BRIDGE-0"
	LINK_BR="$NODE-$BRIDGE-1"

	ip link add $LINK_IF type veth peer name $LINK_BR
	ip link set $LINK_IF netns $NODE
	ip link set $LINK_BR master $BRIDGE

	ip -n $NODE addr add "$ADDRESS/$MASK" dev $LINK_IF
	ip -n $NODE link set $LINK_IF up
	ip -n $NODE link set up dev lo

	ip link set $LINK_BR up
}

netjail_node_unlink_bridge() {
	NODE=$1
	BRIDGE=$2
	
	LINK_BR="$NODE-$BRIDGE-1"

	ip link delete $LINK_BR
}

netjail_node_add_nat() {
	NODE=$1
	ADDRESS=$2
	MASK=$3

	ip netns exec $NODE iptables -t nat -A POSTROUTING -s "$ADDRESS/$MASK" -j MASQUERADE
}

netjail_node_add_default() {
	NODE=$1
	ADDRESS=$2

	ip -n $NODE route add default via $ADDRESS
}

netjail_node_exec() {
	NODE=$1
	FD_IN=$2
	FD_OUT=$3
	shift 3

	unshare -fp --kill-child -- ip netns exec $NODE sudo -u $JAILOR -- $@ 1>& $FD_OUT 0<& $FD_IN
}


