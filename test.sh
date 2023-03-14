#!/bin/sh
set -o errexit -o nounset

course_listing_dir="course_material/perfaware/part1"
testing_dir="tests"

test -d "$course_listing_dir"

rm -rf "$testing_dir"
mkdir -p  "$testing_dir"

for listing in "$course_listing_dir"/*.asm ; do
	test -f "$listing"
	output="${listing##*/}"
	output="${testing_dir}/${output%.asm}"

	ref_output="${output}_ref"
	test_output="${output}_test"

	nasm -o "$ref_output" "$listing"
	./decoder < "$ref_output" > "${test_output}.asm"
	nasm -o "$test_output" "${test_output}.asm"

	if cmp "$ref_output" "$test_output" ; then
		printf "%s: O\n" "$listing"
	else
		printf "%s: X\n" "$listing"
	fi
done
