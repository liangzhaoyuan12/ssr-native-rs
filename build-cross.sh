#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_DIR/build"

# Parse project name and version from Cargo.toml
PROJECT_NAME=$(grep '^name =' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/name = "\(.*\)"/\1/')
PROJECT_VERSION=$(grep '^version =' "$PROJECT_DIR/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')

mkdir -p "$BUILD_DIR"

TARGETS=(
    aarch64-apple-darwin
    aarch64-linux-android
    aarch64-pc-windows-gnullvm
    aarch64-pc-windows-msvc
    aarch64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    i686-pc-windows-gnu
    i686-pc-windows-gnullvm
    i686-pc-windows-msvc
    i686-unknown-linux-gnu
    i686-unknown-linux-musl
    loongarch64-unknown-linux-gnu
    loongarch64-unknown-linux-musl
    riscv64gc-unknown-linux-gnu
    riscv64gc-unknown-linux-musl
    x86_64-apple-darwin
    x86_64-pc-windows-gnu
    x86_64-pc-windows-gnullvm
    x86_64-pc-windows-msvc
    x86_64-unknown-linux-gnu
    x86_64-unknown-linux-musl
)

BINARIES=("ssr-client" "ssr-server")

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Result tracking
declare -A BUILD_RESULT  # "target" -> "SUCCESS" | "FAIL" | "SKIP"

build_for_target() {
    local target="$1"

    # ── Add target ──
    local channel="stable"
    case "$target" in
        loongarch64-* | *-gnullvm)
            channel="nightly"
            ;;
    esac

    local toolchain=""
    [ "$channel" = "nightly" ] && toolchain="+nightly "

    if ! rustup target add ${toolchain}"$target" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠  rustup target add failed, skipping${NC}"
        BUILD_RESULT["$target"]="SKIP"
        return 1
    fi

    # ── Build ──
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN} Building:${NC} ${BOLD}$target${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo ""

    local build_log
    build_log=$(mktemp)
    set +e
    cargo ${toolchain}build --release --target "$target" 2>&1 | tee "$build_log"
    local exit_code=${PIPESTATUS[0]}
    set -e

    if [ "$exit_code" -ne 0 ]; then
        echo -e "\n  ${RED}✘ Build FAILED for $target (exit code: $exit_code)${NC}"
        BUILD_RESULT["$target"]="FAIL"
        rm -f "$build_log"
        return 1
    fi

    rm -f "$build_log"

    # ── Package ──
    local target_dir="$PROJECT_DIR/target/$target/release"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    local has_files=0
    for bin in "${BINARIES[@]}"; do
        local src
        case "$target" in
            *-windows-*)
                src="$target_dir/${bin}.exe"
                ;;
            *)
                src="$target_dir/$bin"
                ;;
        esac

        if [ -f "$src" ]; then
            cp "$src" "$tmp_dir/"
            has_files=1
            echo -e "  ${GREEN}✔${NC} Packaged: $bin"
        else
            echo -e "  ${YELLOW}⚠${NC} $bin not found for $target"
        fi
    done

    if [ "$has_files" -eq 0 ]; then
        echo -e "  ${YELLOW}⚠  No binaries found, skipping archive${NC}"
        BUILD_RESULT["$target"]="SKIP"
        rm -rf "$tmp_dir"
        return 1
    fi

    local archive_name="${PROJECT_NAME}_${PROJECT_VERSION}_${target}.tar.gz"
    local archive_path="$BUILD_DIR/$archive_name"

    tar -czf "$archive_path" -C "$tmp_dir" .
    local size
    size=$(du -h "$archive_path" | cut -f1)
    echo -e "  ${GREEN}✔${NC} Archive: $(basename "$archive_path") (${size})"

    rm -rf "$tmp_dir"
    BUILD_RESULT["$target"]="SUCCESS"
    return 0
}

# ============================================================
#  Main build loop
# ============================================================
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  ${PROJECT_NAME} v${PROJECT_VERSION}${NC}"
echo -e "${BOLD}  Cross-compile & package${NC}"
echo -e "${BOLD}  Output: ${BUILD_DIR}${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

for target in "${TARGETS[@]}"; do
    build_for_target "$target" || true
done

# ============================================================
#  Summary
# ============================================================
echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  Build Summary${NC}"
echo -e "${BOLD}========================================${NC}"

success_count=0
fail_count=0
skip_count=0

for target in "${TARGETS[@]}"; do
    result="${BUILD_RESULT["$target"]}"
    case "$result" in
        SUCCESS)
            echo -e "  ${GREEN}✔${NC} ${BOLD}$target${NC}  ${GREEN}SUCCESS${NC}"
            ((success_count++)) || true
            ;;
        FAIL)
            echo -e "  ${RED}✘${NC} ${BOLD}$target${NC}  ${RED}FAIL${NC}"
            ((fail_count++)) || true
            ;;
        SKIP)
            echo -e "  ${YELLOW}⚠${NC} ${BOLD}$target${NC}  ${YELLOW}SKIPPED${NC}"
            ((skip_count++)) || true
            ;;
        *)
            echo -e "  ${YELLOW}⚠${NC} ${BOLD}$target${NC}  ${YELLOW}UNKNOWN${NC}"
            ((skip_count++)) || true
            ;;
    esac
done

echo ""
echo -e "${BOLD}  Total  :${NC} ${#TARGETS[@]}"
echo -e "${GREEN}  Success: ${success_count}${NC}"
echo -e "${RED}  Failed : ${fail_count}${NC}"
echo -e "${YELLOW}  Skipped: ${skip_count}${NC}"
echo ""

if [ "$success_count" -gt 0 ]; then
    echo -e "${BOLD}Archives:${NC}"
    ls -lh "$BUILD_DIR"/*.tar.gz 2>/dev/null | sed 's/^/  /' || true
fi

echo ""
echo -e "${BOLD}========================================${NC}"
echo ""
