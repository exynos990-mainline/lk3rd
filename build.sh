#!/bin/bash

boards=("maestro9610" "universal9630" "maestro9820" "smdk9830" "universal9830_bringup" "phoenix9830" "c1s" "c2s" "r8s" "x1s" "y2s" "z3s" "erd3830" "universal3830")

user_mode=false
debug_mode=0
board=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		-u|--user)
			user_mode=true
			shift
			;;
		-d|--debug)
			case "$2" in
				y) debug_mode=1 ;;
				n) debug_mode=-1 ;;
				*) echo "Invalid parameter for --debug. Use 'y' or 'n'."; exit 1 ;;
			esac
			shift 2
			;;
		*)
			if [[ -n "$board" ]]; then
				board="Board name is already set."
			else
				board="$1"
			fi
			shift
			;;
	esac
done

echo -e "\n-----------------------------------------------------------------"
echo "Board: $board"
echo "User mode: $user_mode"
echo "Debug mode: $debug_mode"
echo "-----------------------------------------------------------------"

if [[ " ${boards[@]} " =~ " $board " ]]; then
	pushd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null
	rm -rf build-$board
	make_cmd="make $board"
	[[ $user_mode == true ]] && make_cmd+=" user"
	make_cmd+=" -j16"

	if [[ $debug_mode -eq -1 ]]; then
		$make_cmd > >(while IFS= read -r line; do printf '\r%*s\r%s' "$(tput cols)" '' "$line"; done) 2>&1 || exit 1
	else
		$make_cmd
	fi
	popd > /dev/null
elif [[ "$board" == "all" ]]; then
	for b in "${boards[@]}"; do
		if [[ ${#b} -eq 3 ]]; then
			args=()
			args+=("$b")
			[[ $user_mode == true ]] && args+=("-u")
			args+=("-d")
			debug_flag="y"
			[[ $debug_mode -le 0 ]] && debug_flag="n"
			args+=("$debug_flag")
			"${BASH_SOURCE[0]}" ${args[@]} || exit 1
		fi
	done
else
	echo "-----------------------------------------------------------------"
	echo "Usage: ./build.sh [board name] [flags]"
	echo "       ./build.sh all [flags]"
	echo ""
	echo "Flags:"
	echo " -u -user            user mode does not enter ramdump mode when a problem occurs."
	echo " -d -debug [y/N]     show make output."
	echo ""
	echo "Available boards:"
	for board in "${boards[@]}"; do
		printf "  %-22s" "$board"
		if [[ $((++count % 3)) -eq 0 ]]; then
			echo ""
		fi
	done
	echo ""
	echo ""
	echo "./build.sh all builds:"
	count=0
	for board in "${boards[@]}"; do
		if [[ ${#board} -eq 3 ]]; then
			printf "  %-4s" "$board"
			if [[ $((++count % 3)) -eq 0 ]]; then
				echo ""
			fi
		fi
	done
	echo "-----------------------------------------------------------------"
	exit 0
fi