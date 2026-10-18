#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: prepare-kernel.sh --kernel PATH --out PATH [options]

Prepare native ARM64 kernel headers and SELinux generated headers.

  --config FILE       Copy this config to OUT/.config, then run olddefconfig.
  --defconfig NAME    Explicitly replace OUT/.config with this ARM64 defconfig.
  --cc EXECUTABLE     Compiler executable (default: CC, otherwise clang).
  --zig EXECUTABLE    Use Zig's bundled Clang for aarch64-linux-gnu.
  -h, --help          Show this help.

With neither config option, an existing OUT/.config is preserved and reused.
For a new output directory, the default is raphael_stock_defconfig. That old
reference profile needs CPU masks 15 / 112 / 128 from raphael_defconfig; this
normalization is printed and applied only when that defconfig is selected.
Use --config with the device's actual kernel config for a device build.

Dependencies: Bash, make, a native gcc (or HOSTCC), bc, and a cross compiler.
--zig also needs Python 3. No packages are installed by this script.
The target kernel itself rejects source/output paths with spaces or colons.
Config and compiler executable paths are passed without shell evaluation.
EOF
}

die() { printf '%s\n' "$*" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n $2 ]] || die "Missing value for $1"; }

kernel= out= config= defconfig= cc= zig=
while (($#)); do
    case $1 in
        --kernel) need_value "$@"; kernel=$2; shift 2 ;;
        --out) need_value "$@"; out=$2; shift 2 ;;
        --config) need_value "$@"; config=$2; shift 2 ;;
        --defconfig) need_value "$@"; defconfig=$2; shift 2 ;;
        --cc) need_value "$@"; cc=$2; shift 2 ;;
        --zig) need_value "$@"; zig=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done
[[ -n $kernel && -n $out ]] || die "--kernel and --out are required."
[[ -z $config || -z $defconfig ]] || die "Choose --config or --defconfig."
[[ -z $cc || -z $zig ]] || die "Choose --cc or --zig."
[[ -f $kernel/Makefile && -f $kernel/Kconfig ]] || die "Invalid kernel source directory: $kernel"
kernel=$(cd -- "$kernel" && pwd -P)
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd -P)
[[ $kernel != "$out" ]] || die "Use a separate --out directory."
[[ $kernel != *[[:space:]:]* && $out != *[[:space:]:]* ]] ||
    die "The target kernel Makefile does not support spaces or colons in source/output paths."
if [[ -n $config ]]; then
    [[ -f $config ]] || die "Config does not exist: $config"
    config=$(realpath -- "$config")
fi
hostcc=${HOSTCC:-gcc}
for tool in make bc "$hostcc"; do
    command -v -- "$tool" >/dev/null || die "Missing build dependency: $tool"
done
[[ -f $kernel/fs/exfat/Kconfig ]] ||
    die "Missing pinned exFAT submodule. Run tools/fetch-sources.py first."

scratch=$(mktemp -d "$out/.rsk-prepare.XXXXXX")
saved_config=
cleanup() {
    local status=$?
    if [[ -n $saved_config ]] && ! cmp -s -- "$saved_config" "$out/.config"; then
        cp -- "$saved_config" "$out/.config"
        printf '%s\n' 'Kernel preparation tried to change the reused config; its original contents were restored.' >&2
        status=1
    fi
    rm -rf -- "$scratch"
    exit "$status"
}
trap cleanup EXIT

if [[ -n $zig ]]; then
    command -v -- "$zig" >/dev/null || die "Zig executable not found: $zig"
    command -v python3 >/dev/null || die "Python 3 is required for --zig."
    export ZIG_GLOBAL_CACHE_DIR=${ZIG_GLOBAL_CACHE_DIR:-$out/.zig-global-cache}
    export ZIG_LOCAL_CACHE_DIR=${ZIG_LOCAL_CACHE_DIR:-$out/.zig-local-cache}
    zig_lib=$("$zig" env | python3 -c 'import json, sys; print(json.load(sys.stdin)["lib_dir"])')
    compiler=("$zig" clang --target=aarch64-linux-gnu "-resource-dir=$zig_lib")
else
    cc=${cc:-${CC:-clang}}
    command -v -- "$cc" >/dev/null || die "Compiler executable not found: $cc (use --zig for Zig)."
    compiler=("$cc")
    if [[ $("$cc" --version) == *clang* ]]; then
        compiler+=(--target=aarch64-linux-gnu)
    fi
fi

# Kbuild expands CC through a shell. A wrapper keeps an executable path with
# spaces as one argument; printf %q writes quoted Bash words, without eval.
write_wrapper() {
    local destination=$1
    shift
    {
        printf '#!/usr/bin/env bash\nexec'
        printf ' %q' "$@"
        printf ' "$@"\n'
    } > "$destination"
    chmod +x -- "$destination"
}
write_wrapper "$scratch/cc" "${compiler[@]}"
write_wrapper "$scratch/hostcc" "$hostcc"
make_cmd=(make -C "$kernel" "O=$out" ARCH=arm64
          "CC=$scratch/cc" "HOSTCC=$scratch/hostcc" CLANG_FLAGS=)

if [[ -n $config ]]; then
    printf 'Using explicit config: %s; Kconfig will normalize the output copy.\n' "$config"
    [[ $config == "$out/.config" ]] || cp -- "$config" "$out/.config"
    "${make_cmd[@]}" olddefconfig
elif [[ -n $defconfig || ! -f $out/.config ]]; then
    defconfig=${defconfig:-raphael_stock_defconfig}
    [[ $defconfig != -* && -f $kernel/arch/arm64/configs/$defconfig ]] ||
        die "ARM64 defconfig not found: $defconfig"
    printf 'Creating output configuration from %s.\n' "$defconfig"
    "${make_cmd[@]}" "$defconfig"
    if [[ $defconfig == raphael_stock_defconfig ]]; then
        printf '%s\n' 'Normalizing the reference CPU masks: LITTLE=15, BIG=112, PRIME=128 (from raphael_defconfig).'
        "$kernel/scripts/config" --file "$out/.config" \
            --set-val LITTLE_CPU_MASK 15 --set-val BIG_CPU_MASK 112 --set-val PRIME_CPU_MASK 128
    fi
    "${make_cmd[@]}" olddefconfig
else
    printf 'Reusing existing configuration without changes: %s\n' "$out/.config"
    saved_config=$scratch/config.original
    cp -- "$out/.config" "$saved_config"
fi

# Reject an implicit config rewrite, and omit the unrelated old vDSO build.
KCONFIG_NOSILENTUPDATE=1 "${make_cmd[@]}" prepare0
mkdir -p -- "$out/scripts/selinux/genheaders" "$out/security/selinux"
"$hostcc" -O2 \
    "-I$kernel/include/uapi" "-I$kernel/include" "-I$kernel/security/selinux/include" \
    "$kernel/scripts/selinux/genheaders/genheaders.c" \
    -o "$out/scripts/selinux/genheaders/genheaders"
"$out/scripts/selinux/genheaders/genheaders" \
    "$out/security/selinux/flask.h" "$out/security/selinux/av_permissions.h"

printf 'Native kernel and SELinux headers are ready in %s\n' "$out"
sha256sum "$out/.config" "$out/include/generated/autoconf.h"
