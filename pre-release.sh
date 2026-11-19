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
        printf 'Build and check the release. Use --publish from a clean release tag to upload to PyPI.\n'
        exit 0
        ;;
    *)
        printf 'Usage: %s [--publish]\n' "$0" >&2
        exit 2
        ;;
esac

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

working_tree=$(git status --porcelain --untracked-files=all)
tag=$(git describe --tags --exact-match HEAD 2>/dev/null) || tag=

if [[ "${1:-}" == --publish ]]; then
    if [[ -n "$working_tree" ]]; then
        printf 'Publishing requires a clean Git working tree.\n' >&2
        exit 1
    fi

    if [[ -z "$tag" ]]; then
        printf 'Publishing requires a Git tag on HEAD.\n' >&2
        exit 1
    fi
fi

release_dir=$(mktemp -d)
printf 'Release artifacts: %s\n' "$release_dir"
source_dir=.
if [[ -z "$working_tree" && -n "$tag" ]]; then
    version=${tag#v}
    source_dir="$release_dir/source"
    mkdir -- "$source_dir"
    git archive HEAD | tar -x -C "$source_dir"
    replacement=$(printf '%s' "$version" | sed 's/[&/]/\\&/g')
    sed "s/^version = .*/version = \"$replacement\"/" "$source_dir/pyproject.toml" > "$source_dir/pyproject.toml.stamped"
    mv -- "$source_dir/pyproject.toml.stamped" "$source_dir/pyproject.toml"
fi
uv build "$source_dir" --out-dir "$release_dir"
artifacts=("$release_dir"/*.whl "$release_dir"/*.tar.gz)
uvx twine check --strict "${artifacts[@]}"

if [[ "${1:-}" == --publish ]]; then
    uvx twine upload --repository pypi --username __token__ "${artifacts[@]}"
fi
