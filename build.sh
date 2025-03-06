#!/bin/bash


boards=("maestro9610" "universal9630" "maestro9820" "smdk9830" "universal9830_bringup" "phoenix9830" "c1s" "c2s" "r8s" "x1s" "y2s" "z3s" "erd3830" "universal3830")

tarball=false
user_mode=false
enable_logging=false
verbose_mode=0
board=""

function print_usage() {
	echo "-----------------------------------------------------------------"
	echo "Usage: ./build.sh [board name] [flags]"
	echo "       ./build.sh all [flags]"
	echo ""
	echo "Flags:"
	echo " -t --tar 		   Create a tarball of the build."
	echo " -u -user            user mode does not enter ramdump mode when a problem occurs."
	echo " -l --log            Enable logging."
	echo " -v -verbose [y/N]   show make output."
	echo " -h --help           Show this help message."
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
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		-h|--help)
			print_usage
			exit 0
			;;
		-t|--tar)
			tarball=true
			shift
			;;
		-u|--user)
			user_mode=true
			shift
			;;
		-l|--log)
			enable_logging=true
			shift
			;;
		-v|--verbose)
			case "$2" in
				y) verbose_mode=1 ;;
				n) verbose_mode=-1 ;;
				*) echo "Invalid parameter for --verbose. Use 'y' or 'n'."; exit 1 ;;
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


if [[ " ${boards[@]} " =~ " $board " ]]; then
	echo -e "\n-----------------------------------------------------------------"
	echo "Board: $board"
	echo "Create tarball: $tarball"
	echo "User mode: $user_mode"
	echo "Enable logging: $enable_logging"
	echo "Verbose mode: $([[ $verbose_mode -eq 1 ]] && echo 'true' || echo 'false')"
	echo "-----------------------------------------------------------------"

	pushd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null
	rm -rf build-$board
	make_cmd="make $board"
	[[ $user_mode == true ]] && make_cmd+=" user"
	[[ $enable_logging == true ]] && make_cmd+=" print_debug"
	make_cmd+=" -j16"
	echo "Running: $make_cmd"

	if [[ $verbose_mode -eq -1 ]]; then
		$make_cmd > >(while IFS= read -r line; do printf '\r%*s\r%s' "$(tput cols)" '' "$line"; done) 2>&1 || exit 1
	else
		$make_cmd
	fi

	rm -rf build/$board
	mkdir -p build/$board

	if [[ $tarball == true ]]; then
		mv boot-$board.img boot.img
		lz4 -B6 --content-size boot.img boot.img.lz4
		tar -c --format=gnu -f boot-$board.tar boot.img.lz4
		rm -f boot.img.lz4
		mv boot-$board.tar build/$board/boot-$board.tar
		mv boot.img boot-$board.img
	fi

	mv build-$board build/$board/
	mv boot-$board.img build/$board/boot-$board.img
	
	popd > /dev/null
elif [[ "$board" == "all" ]]; then
	rm -r "$(dirname "${BASH_SOURCE[0]}")/build/all/"
	for b in "${boards[@]}"; do
		if [[ ${#b} -eq 3 ]]; then
			args=()
			args+=("$b")
			[[ $user_mode == true ]] && args+=("-u")
			[[ $enable_logging == true ]] && args+=("-l")
			[[ $tarball == true ]] && args+=("-t")
			args+=("-v")
			verbose_flag="y"
			[[ $verbose_mode -le 0 ]] && verbose_flag="n"
			args+=("$verbose_flag")
			"${BASH_SOURCE[0]}" ${args[@]} || exit 1

			mkdir -p "$(dirname "${BASH_SOURCE[0]}")/build/all/"
			ln -s "$(realpath "$(dirname "${BASH_SOURCE[0]}")/build/$b/boot-$b.img")" "$(realpath "$(dirname "${BASH_SOURCE[0]}")/build/all/boot-$b.img")"
			if [[ $tarball == true ]]; then
				ln -s "$(realpath "$(dirname "${BASH_SOURCE[0]}")/build/$b/boot-$b.tar")" "$(realpath "$(dirname "${BASH_SOURCE[0]}")/build/all/boot-$b.tar")"
			fi
		fi
	done
else
	echo "Invalid parameters"
	print_usage
	exit 1
fi