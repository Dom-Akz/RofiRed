#!/usr/bin/env bash

# Verify the integrity of the policy files by comparing the hash (sha-256)
# The script will produce a `REJECTED` resutl in this tow cases:
#   if it did not find the hash files
#   if the hash did not match

manifest="../integrity/policy.manifest.json"

reject() {
	echo "REJECTED"
	exit 1
}

[[ -f "$manifest" ]] || reject

count=$(jq '.files | length' "$manifest" 2>/dev/null) || reject
[[ "$count" -gt 0 ]] || reject

while IFS=$'\t' read -r file hash; do
	[ -f "$file" ] || reject
	actual=$(sha256sum "$file" | cut -d' ' -f1)
	[[ "$actual" = "$hash" ]] || reject
done < <(jq -r '.files[] | [.file, .hash] | @tsv' "$manifest")

echo "ACCEPTED"
exit 0
