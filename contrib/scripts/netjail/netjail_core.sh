#!/bin/sh
# 

JAILOR=${SUDO_USER:?must run in sudo}

# running with `sudo` is required to be
# able running the actual commands as the
# original user.

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

netjail_opt() {
	local OPT=$1
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

netjail_opts() {
	local OPT=$1
	local DEF=$2
	shift 2
	
	while [ $# -gt 0 ]; do
		if [ "$1" = "$OPT" ]; then
			printf "$2"
			return
		fi

		shift 1
	done
	
	printf "$DEF"
}

netjail_check() {
	local NODE_COUNT=$1
	local FD_COUNT=$(($(ls /proc/self/fd | wc -w) - 4))

	# quit if `$FD_COUNT < ($LOCAL_M * $GLOBAL_N * 2)`:
	# the script also requires `sudo -C ($FD_COUNT + 4)`
	# so you need 'Defaults closefrom_override' in the
	# sudoers file.

	if [ $FD_COUNT -lt $(($NODE_COUNT * 2)) ]; then
		echo "File descriptors do not match requirements!" >&2
		exit 1
	fi
}

netjail_check_bin() {
	local PROGRAM=$1
	local MATCH=$(ls $(echo $PATH | tr ":" "\n") | grep "^$PROGRAM\$" | tr "\n" " " | awk '{ print $1 }')

	# quit if the required binary $PROGRAM can not be
	# found in the used $PATH.

	if [ "$MATCH" != "$PROGRAM" ]; then
		echo "Required binary not found: $PROGRAM" >&2
		exit 1
	fi
}

netjail_print_name() {
	printf "%s%02x%02x" $1 $2 ${3:-0}
}

netjail_bridge() {
	local BRIDGE=$1

	ip link add $BRIDGE type bridge
	ip link set dev $BRIDGE up
}

netjail_bridge_clear() {
	local BRIDGE=$1

	ip link delete $BRIDGE
}

netjail_node() {
	local NODE=$1

	ip netns add $NODE
}

netjail_node_clear() {
	local NODE=$1

	ip netns delete $NODE
}

netjail_node_link_bridge() {
	local NODE=$1
	local BRIDGE=$2
	local ADDRESS=$3
	local MASK=$4
	
	local LINK_IF="$NODE-$BRIDGE-0"
	local LINK_BR="$NODE-$BRIDGE-1"

	ip link add $LINK_IF type veth peer name $LINK_BR
	ip link set $LINK_IF netns $NODE
	ip link set $LINK_BR master $BRIDGE

	ip -n $NODE addr add "$ADDRESS/$MASK" dev $LINK_IF
	ip -n $NODE link set $LINK_IF up
	ip -n $NODE link set up dev lo

	ip link set $LINK_BR up
}

netjail_node_unlink_bridge() {
	local NODE=$1
	local BRIDGE=$2
	
	local LINK_BR="$NODE-$BRIDGE-1"

	ip link delete $LINK_BR
}

netjail_node_add_nat() {
	local NODE=$1
	local ADDRESS=$2
	local MASK=$3

	ip netns exec $NODE iptables -t nat -A POSTROUTING -s "$ADDRESS/$MASK" -j MASQUERADE
}

netjail_node_add_default() {
	local NODE=$1
	local ADDRESS=$2

	ip -n $NODE route add default via $ADDRESS
}

netjail_node_exec() {
	local NODE=$1
	local FD_IN=$2
	local FD_OUT=$3
	shift 3

	unshare -fp --kill-child -- ip netns exec $NODE sudo -u $JAILOR -- $@ 1>& $FD_OUT 0<& $FD_IN
}

netjail_kill() {
	local PID=$1
	local MATCH=$(ps --pid $PID | awk "{ if ( \$1 == $PID ) { print \$1 } }" | wc -l)

	if [ $MATCH -gt 0 ]; then
		kill -n 19 $PID

		for CHILD in $(ps -o pid,ppid -ax | awk "{ if ( \$2 == $PID ) { print \$1 } }"); do
			netjail_kill $CHILD
		done

		kill $PID
	fi
}

netjail_killall() {
	if [ $# -gt 0 ]; then
		local PIDS=$1

		for PID in $PIDS; do
			netjail_kill $PID
		done
	fi
}

netjail_waitall() {
	if [ $# -gt 0 ]; then
		local PIDS=$1

		for PID in $PIDS; do
			wait $PID
		done
	fi
}

