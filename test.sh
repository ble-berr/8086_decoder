#!/bin/sh
set -o errexit -o nounset

mkdir -p tests

for listing in listings/*.asm ; do
	output="${listing#listings/}"
	output="tests/${output%.asm}"

	ref_output="${output}_ref"
	test_output="${output}_test"

	nasm -o "$ref_output" "$listing"
	./emu < "$ref_output" > "${test_output}.asm"
	nasm -o "$test_output" "${test_output}.asm"

	if cmp "$ref_output" "$test_output" ; then
		printf "%s: O\n" "$listing"
	else
		printf "%s: X\n" "$listing"
	fi
done
