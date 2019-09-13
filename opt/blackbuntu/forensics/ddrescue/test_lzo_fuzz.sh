#!/bin/bash

LZOP=`type -p lzop || type -P true`

test_fuzz()
{
	ERC=$1
	ERCM=$2
	PAR=$3
	EDIFF=$4
	shift 4
	echo ./fuzz_lzo $* dd_rescue dd_rescue.lzo
	./fuzz_lzo $* dd_rescue dd_rescue.lzo || exit 1
	echo ./dd_rescue -tL ./libddr_lzo.so$PAR dd_rescue.lzo dd_rescue.cmp
	./dd_rescue -tL ./libddr_lzo.so$PAR dd_rescue.lzo dd_rescue.cmp
	RC=$?
	if test $RC -lt $ERC -o $RC -gt $ERCM; then echo "Unexpected exit value $RC (exp: $ERC-$ERCM)"; exit 2; fi
	echo "Exit code $RC, good"
	echo -n "# of differences: "
       	DIFF=`cmp -l dd_rescue dd_rescue.cmp | wc -l`
	echo $DIFF
	if test "$DIFF" -gt "$EDIFF"; then echo "More differences than expected ..."; exit 3; fi
}


./fuzz_lzo dd_rescue dd_rescue.lzo
$LZOP -vl dd_rescue.lzo
./dd_rescue -L ./libddr_lzo.so dd_rescue.lzo /dev/null

# Main tests ...
test_fuzz 0 0 "" 0 -m3
test_fuzz 1 1 "" 16384 -U2
test_fuzz 1 1 "=nodiscard" 0 -U2
test_fuzz 1 1 "=nodiscard" 0 -C2
test_fuzz 1 5 "" 16384 -x1:0x6fe=0x1a
test_fuzz 1 6 "=nodiscard" 16384 -x1:0x6fe=0x1a
test_fuzz 1 3 "" 16384 -u2=8192
test_fuzz 1 131 "" 100000 -c1=8192
# TODO: A lot more tests, with and without nodiscard
# TODO: Do tests with -T, with good preexisting data and check whether nothing gets destroyed
rm -f dd_rescue.lzo dd_rescue.cmp

