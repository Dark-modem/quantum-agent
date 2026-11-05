# fix_installers.py — apply the RELEASE-REQUESTS fixes to both installers.

# ---------------- install-agent.sh ----------------
p = "install-agent.sh"
s = open(p, encoding="utf-8").read()

# 1. flag variable
s = s.replace(
    'SSH_PORT="" ENABLE_FIREWALL=0 WITH_FAIL2BAN=0 NO_START=0 CHECK_ONLY=0 ASSUME_YES=0',
    'SSH_PORT="" ENABLE_FIREWALL=0 WITH_FAIL2BAN=0 NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0 ASSUME_YES=0')
# 2. flag parse
s = s.replace(
    '        --check)         CHECK_ONLY=1; shift;;',
    '        --check)         CHECK_ONLY=1; shift;;\n'
    '        --verify-only)   VERIFY_ONLY=1; shift;;')

# 3. verify_binary helper + reordered main
old_main = '''# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
need_root
need_systemd
if [[ $CHECK_ONLY -eq 1 ]]; then check_install; fi   # read-only, exits

info "installing quantum-agent (arch $(arch_tag), version ${VERSION})"
'''
new_main = '''# ---------------------------------------------------------------------------
# verify_binary_only: checksum verification WITHOUT root/systemd (the
# offline-bundle path: `--verify-only --binary ... --checksum ...`).
# ---------------------------------------------------------------------------
verify_binary_only() {
    local arch; arch="$(arch_tag)"
    local src want got
    if [[ -n "$BINARY" ]]; then
        src="$BINARY"
        [[ -r "$src" ]] || die "verify-only: cannot read --binary: $src"
        [[ -n "$CHECKSUM" ]] || die "verify-only: --binary requires --checksum (or a ${src}.sha256 sidecar)"
        got="$(trun 60 sha256sum "$src" | awk '{print $1}')"
        [[ "$got" == "$CHECKSUM" ]] \\
            || die "checksum mismatch for $src
  expected: $CHECKSUM
  got:      $got"
        info "checksum verified: $src = $got"
        return 0
    fi
    # No --binary: download from the release and verify (network needed).
    have curl || have wget || die "verify-only: need curl/wget (or pass --binary)"
    if [[ "$VERSION" == "latest" ]]; then
        VERSION="$(release_latest)" || die "verify-only: cannot resolve the latest release tag"
    fi
    local url_base="https://github.com/${REPO}/releases/download/${VERSION}"
    local asset="quantum-agent-linux-${arch}"
    src="$(mktemp -t quantum-verify.XXXXXX)"
    download "$url_base/$asset" "$src" || die "verify-only: download failed: $asset"
    local sums; sums="$(mktemp -t quantum-sums.XXXXXX)"
    download "$url_base/checksums.txt" "$sums" || die "verify-only: download failed: checksums.txt"
    want="$(trun 10 awk -v a="$asset" '$2==a || $2=="*"a {print $1}' "$sums")"
    [[ -n "$want" ]] || die "verify-only: checksums.txt has no entry for $asset"
    got="$(trun 60 sha256sum "$src" | awk '{print $1}')"
    [[ "$got" == "$want" ]] \\
        || die "checksum mismatch for $asset
  expected: $want
  got:      $got"
    info "checksum verified: $asset = $got"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if [[ $VERIFY_ONLY -eq 1 ]]; then verify_binary_only; exit 0; fi   # no root/systemd needed
need_root
if [[ $CHECK_ONLY -eq 1 ]]; then
    need_systemd
    check_install
fi

info "installing quantum-agent (arch $(arch_tag), version ${VERSION})"
install_binary
# Binary + checksum verified (fetch_binary dies on mismatch BEFORE this
# point): only NOW do we require systemd for the unit/service work.
need_systemd
'''
assert old_main in s, "agent main anchor missing"
s = s.replace(old_main, new_main)
open(p, "w", encoding="utf-8", newline="\n").write(s)
print("install-agent.sh patched")

# ---------------- install-panel.sh ----------------
p = "install-panel.sh"
s = open(p, encoding="utf-8").read()

s = s.replace('NO_START=0 CHECK_ONLY=0', 'NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0')
s = s.replace('        --check)          CHECK_ONLY=1; shift;;',
              '        --check)          CHECK_ONLY=1; shift;;\n'
              '        --verify-only)    VERIFY_ONLY=1; shift;;')

old_main = '''# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
need_root
need_systemd
if [[ $CHECK_ONLY -eq 1 ]]; then check_install; fi
info "installing quantum-panel (arch $(arch_tag), version ${VERSION})"
install_binary'''
new_main = '''# ---------------------------------------------------------------------------
# verify_binary_only: checksum verification WITHOUT root/systemd.
# ---------------------------------------------------------------------------
verify_binary_only() {
    local arch; arch="$(arch_tag)"
    local src want got
    if [[ -n "$BINARY" ]]; then
        src="$BINARY"
        [[ -r "$src" ]] || die "verify-only: cannot read --binary: $src"
        [[ -n "$CHECKSUM" ]] || die "verify-only: --binary requires --checksum (or a ${src}.sha256 sidecar)"
        got="$(trun 60 sha256sum "$src" | awk '{print $1}')"
        [[ "$got" == "$CHECKSUM" ]] \\
            || die "checksum mismatch for $src
  expected: $CHECKSUM
  got:      $got"
        info "checksum verified: $src = $got"
        return 0
    fi
    have curl || have wget || die "verify-only: need curl/wget (or pass --binary)"
    if [[ "$VERSION" == "latest" ]]; then
        VERSION="$(release_latest)" || die "verify-only: cannot resolve the latest release tag"
    fi
    local base="https://github.com/${REPO}/releases/download/${VERSION}"
    local asset="quantum-panel-linux-${arch}"
    src="$(mktemp -t quantum-verify.XXXXXX)"
    download "$base/$asset" "$src" || die "verify-only: download failed: $asset"
    local sums; sums="$(mktemp -t quantum-sums.XXXXXX)"
    download "$base/checksums.txt" "$sums" || die "verify-only: download failed: checksums.txt"
    want="$(trun 10 awk -v a="$asset" '$2==a || $2=="*"a {print $1}' "$sums")"
    [[ -n "$want" ]] || die "verify-only: checksums.txt has no entry for $asset"
    got="$(trun 60 sha256sum "$src" | awk '{print $1}')"
    [[ "$got" == "$want" ]] \\
        || die "checksum mismatch for $asset
  expected: $want
  got:      $got"
    info "checksum verified: $asset = $got"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
if [[ $VERIFY_ONLY -eq 1 ]]; then verify_binary_only; exit 0; fi   # no root/systemd needed
need_root
if [[ $CHECK_ONLY -eq 1 ]]; then
    need_systemd
    check_install
fi
info "installing quantum-panel (arch $(arch_tag), version ${VERSION})"
install_binary
# Binary + checksum verified (fetch_binary dies on mismatch BEFORE this
# point): only NOW do we require systemd for the unit/service work.
need_systemd'''
assert old_main in s, "panel main anchor missing"
s = s.replace(old_main, new_main)

# SC2015 fix: A && B || C → proper if in check_install
s = s.replace(
    '''    [[ -f "$UNIT" ]] && grep -q "ProtectSystem=strict" "$UNIT" && info "hardened unit present" || warn "unit missing or not hardened"''',
    '''    if [[ -f "$UNIT" ]] && grep -q "ProtectSystem=strict" "$UNIT"; then
        info "hardened unit present"
    else
        warn "unit missing or not hardened"
    fi''')

open(p, "w", encoding="utf-8", newline="\n").write(s)
print("install-panel.sh patched")
