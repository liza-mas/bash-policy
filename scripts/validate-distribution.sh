#!/bin/sh
set -u

GO_CMD=${GO:-go}

run_distribution_check() {
	category=$1
	shift

	printf 'distribution validation: %s\n' "$category"
	"$@"
	status=$?
	if [ "$status" -eq 0 ]; then
		return 0
	fi

	printf 'distribution validation failed: %s\n' "$category" >&2
	return "$status"
}

run_distribution_check "test suite" "$GO_CMD" test ./... || exit $?
run_distribution_check "source build" make build || exit $?
