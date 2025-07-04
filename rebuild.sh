#!/usr/bin/env bash
# Everything you push to main will do a test build, and let you know if it breaks.
#
# Things only get released if you tag it. And the actual build is based on the tag.
# Without tagging it, nothing is released and it doesn't affect anyone at all, aside
# from people building it from source.
#
# Look at the list of tags:
#
# https://github.com/betrusted-io/rust/tags
#
# We increment the 4th decimal. So far with the 1.59.0 branch, we've had two releases: 1.59.0.1 and 1.59.0.2. If you decided to release a new version of libstd, you would do:
#
# git tag -a 1.59.0.3 # Commit a message, indicating what you've changed
# git push --tags
#
# That would build and release a new version.

set -e
set -u
# set -x
set -o pipefail

usage() {
    echo "Usage: $0 [-t <riscv32imac-unknown-xous-elf|armv7a-unknown-xous-elf>]"
    exit 1
}

while getopts "t:" o; do
    case "${o}" in
        t)
            target=$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done

target=${target:-riscv32imac-unknown-xous-elf}

rust_sysroot=$(rustc --print sysroot)

export RUST_COMPILER_RT_ROOT="$(pwd)/src/llvm-project/compiler-rt"
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_OPT_LEVEL="3"
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="false"
export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="-Cforce-unwind-tables=yes -Cembed-bitcode=yes -Zforce-unstable-if-unmarked"
export __CARGO_DEFAULT_LIB_METADATA="stablestd"

command_exists() {
    which $1 &> /dev/null && $1 --version 2>&1 > /dev/null
}

# Set up the C compiler. We need to explicitly specify these variables
# because the `cc` package obviously doesn't recognize our target triple.
case "$target" in
    riscv32imac-unknown-xous-elf)
        if command_exists riscv32-unknown-elf-gcc
        then
            export CC="riscv32-unknown-elf-gcc"
            export AR="riscv32-unknown-elf-ar"
        elif command_exists riscv-none-embed-gcc
        then
            export CC ="riscv-none-embed-gcc"
            export AR ="riscv-none-embed-ar"
        elif command_exists riscv64-unknown-elf-gcc
        then
            export CC="riscv64-unknown-elf-gcc"
            export AR="riscv64-unknown-elf-ar"
        else
            echo "No C compiler found for riscv" 1>&2
            exit 1
        fi
        ;;

    armv7a-unknown-xous-elf)
        if command_exists arm-none-eabi-gcc
        then
            export CC="arm-none-eabi-gcc"
            export AR="arm-none-eabi-ar"
        else
            echo "No C compiler found for arm" 1>&2
            exit 1
        fi
        ;;
    *)
        echo "Invalid toolchain triple" 1>&2
        exit 1
        ;;
esac

# Patch llvm's source to not enable `u128` for our riscv32imac.
if [ "$target" == "riscv32imac-unknown-xous-elf" ]; then
    line_to_remove="define CRT_HAS_128BIT"
    file_to_patch="./src/llvm-project/compiler-rt/lib/builtins/int_types.h"
    sed -e "/$line_to_remove/d" "$file_to_patch" > "$file_to_patch.tmp"
    mv "$file_to_patch.tmp" "$file_to_patch"
fi

src_path="./library/target/$target/release/deps"
dest_path="$rust_sysroot/lib/rustlib/$target"
dest_lib_path="$dest_path/lib"

mkdir -p $dest_lib_path

if [ ! -e "$dest_path/target.json" ]
then
    cp "$target.json" "$dest_path/target.json"
fi

rustc --version | awk '{print $2}' > "$dest_path/RUST_VERSION"

# Remove stale objects
rm -f $dest_lib_path/*.rlib

# TODO: Use below to remove duplicates
# previous_libraries=$(ls -1 $src_path/*.rlib || echo "")

RUSTFLAGS="$RUSTFLAGS --cfg keyos --check-cfg=cfg(keyos)" cargo build \
    --target ${target} \
    -Zbinary-dep-depinfo \
    --release \
    --features "panic-unwind compiler-builtins-c compiler-builtins-mem" \
    --manifest-path "library/sysroot/Cargo.toml" || exit 1

# TODO: Remove duplicates here by comparing it with $previous_libraries
for new_item in $(ls -1 $src_path/*.rlib)
do
    file=$(basename $new_item)
    base_string=$(echo $file | rev | cut -d- -f2- | rev)
done

cp $src_path/*.rlib "$dest_lib_path"
