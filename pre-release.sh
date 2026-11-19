#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
    ""|--publish)
        if (( $# > 1 )); then
            printf 'Usage: %s [--publish]\n' "$0" >&2
            exit 2
        fi
        ;;
    -h|--help)
        printf 'Usage: %s [--publish]\n' "$0"
        printf 'Build and check the release. Use --publish to upload to PyPI.\n'
        exit 0
        ;;
    *)
        printf 'Usage: %s [--publish]\n' "$0" >&2
        exit 2
        ;;
esac

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
release_dir=$(mktemp -d)
printf 'Release artifacts: %s\n' "$release_dir"
uv build --out-dir "$release_dir"
artifacts=("$release_dir"/*.whl "$release_dir"/*.tar.gz)
uvx twine check --strict "${artifacts[@]}"

if [[ "${1:-}" == --publish ]]; then
    uvx twine upload --repository pypi --username __token__ "${artifacts[@]}"
fi
