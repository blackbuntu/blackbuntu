#!/bin/bash

LZOP=`type -p lzop` # || type -P true`

compress_ddr_lzop_and_compare()
{
	test -n "$LZOP" || return
	echo "*** Test dd_r/lzop $1 ($2)"
	./dd_rescue -qATL ./libddr_lzo.so=benchmark:algo=$2:compress $1 $1.ddr.lzo || exit 1
	$LZOP -d $1.ddr.lzo || exit 2
	cmp $1.ddr $1 || exit 3
	rm $1.ddr.lzo $1.ddr
}

compress_lzop_ddr_and_compare()
{
	test -n "$LZOP" || return
	echo "*** Test lzop/dd_r $1 ($2)"
	$LZOP $2 $1 -o $1.lzop.lzo || exit 4
	./dd_rescue -qATL ./libddr_lzo.so=benchmark:decompress $1.lzop.lzo $1.lzop || exit 5
	cmp $1.lzop $1 || exit 6
	rm $1.lzop $1.lzop.lzo
}

compress_ddr_ddr_and_compare()
{
	echo "*** Test dd_r/dd_r $1 ($2)"
	./dd_rescue -qATL ./libddr_lzo.so=benchmark:algo=$2:compress $1 $1.ddr.lzo || exit 7
	#$LZOP -t $1.ddr.lzo || exit 8
	./dd_rescue -qATL ./libddr_lzo.so=benchmark:decompress $1.ddr.lzo $1.ddr || exit 8
	cmp $1.ddr $1 || exit 9
	rm $1.ddr.lzo $1.ddr
}


for name in "$@"; do
	for alg in lzo1x_1 lzo1x_1_15 lzo1x_999; do
		if test ! -r "$name"; then continue; fi
		compress_ddr_lzop_and_compare "$name" $alg
		compress_ddr_ddr_and_compare "$name" $alg
	done
	for alg in -1 -5 -9; do
		if test ! -r "$name"; then continue; fi
		compress_lzop_ddr_and_compare "$name" $alg
	done
	true
done

