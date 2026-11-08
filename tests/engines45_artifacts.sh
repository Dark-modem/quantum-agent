#!/usr/bin/env bash
# engines45_artifacts.sh — runs INSIDE WSL on the native /tmp filesystem
# (the /mnt/c large-file reads flake under Windows AV locks): fetch the
# upstream releases, repack into the agent extract shape (tarball WITH a
# directory entry, ELF magic asserted), ship the upstream LICENSE, sign
# with a dev ed25519 key (outside repos), and write the runner env pins.
set -uo pipefail
ART=/var/tmp/eng45-art; rm -rf "$ART"; mkdir -p "$ART/pub/pk/api/agent/artifact" "$ART/pub/pk/api/agent/engine-artifacts/file" "$ART/pub/lic"
WSVER=10.1.9; CHVER=1.10.1; FRVER=0.61.1
try3() { for i in 1 2 3; do "$@" && return 0; sleep 2; done; return 1; }
fetch() { [ -s "$2" ] && { echo "  cached: $(basename "$2")"; return 0; }; curl -fsSL --retry 2 -o "$2" "$1" && echo "  got $(basename "$2")" && return 0; return 1; }

fetch "https://github.com/fatedier/frp/releases/download/v$FRVER/frp_${FRVER}_linux_amd64.tar.gz" "$ART/frp_${FRVER}_linux_amd64.tar.gz" || exit 1
fetch "https://github.com/fatedier/frp/releases/download/v$FRVER/frp_${FRVER}_linux_arm64.tar.gz" "$ART/frp_${FRVER}_linux_arm64.tar.gz" || exit 1
[ "$(stat -c%s "$ART/frp_${FRVER}_linux_amd64.tar.gz")" -gt 10000000 ] || { echo "frp amd64 truncated"; exit 1; }
CH_AMD=""; for n in chisel_${CHVER}_linux_amd64.gz chisel_v${CHVER}_linux_amd64.gz; do fetch "https://github.com/jpillora/chisel/releases/download/v$CHVER/$n" "$ART/$n" && CH_AMD="$ART/$n" && break; done
CH_ARM=""; for n in chisel_${CHVER}_linux_arm64.gz chisel_v${CHVER}_linux_arm64.gz; do fetch "https://github.com/jpillora/chisel/releases/download/v$CHVER/$n" "$ART/$n" && CH_ARM="$ART/$n" && break; done
[ -n "$CH_AMD" ] && [ -n "$CH_ARM" ] || { echo "chisel fetch failed"; exit 1; }
[ "$(stat -c%s "$CH_AMD")" -gt 3000000 ] || { echo "chisel amd64 truncated"; exit 1; }
WS_AMD=""; for n in wstunnel_v${WSVER}_x86_64-unknown-linux-musl.tar.gz wstunnel_${WSVER}_x86_64-unknown-linux-musl.tar.gz wstunnel_${WSVER}_linux_amd64.tar.gz wstunnel_v${WSVER}_linux_amd64.tar.gz; do fetch "https://github.com/erebe/wstunnel/releases/download/v$WSVER/$n" "$ART/$n" && WS_AMD="$ART/$n" && break; done
WS_ARM=""; for n in wstunnel_v${WSVER}_aarch64-unknown-linux-musl.tar.gz wstunnel_${WSVER}_aarch64-unknown-linux-musl.tar.gz wstunnel_${WSVER}_linux_arm64.tar.gz wstunnel_v${WSVER}_linux_arm64.tar.gz; do fetch "https://github.com/erebe/wstunnel/releases/download/v$WSVER/$n" "$ART/$n" && WS_ARM="$ART/$n" && break; done
[ -n "$WS_AMD" ] && [ -n "$WS_ARM" ] || { echo "wstunnel fetch failed"; exit 1; }
[ "$(stat -c%s "$WS_AMD")" -gt 2000000 ] || { echo "wstunnel amd64 truncated"; exit 1; }
echo "  all upstream artifacts present"

fetch "https://raw.githubusercontent.com/fatedier/frp/v$FRVER/LICENSE" "$ART/pub/lic/LICENSE-frp.txt" || echo "  WARN frp license"
fetch "https://raw.githubusercontent.com/erebe/wstunnel/v$WSVER/LICENSE" "$ART/pub/lic/LICENSE-wstunnel.txt" || echo "  WARN wstunnel license"
fetch "https://raw.githubusercontent.com/jpillora/chisel/v$CHVER/LICENSE" "$ART/pub/lic/LICENSE-chisel.txt" || echo "  WARN chisel license"
for f in LICENSE-frp.txt LICENSE-wstunnel.txt LICENSE-chisel.txt; do [ -s "$ART/pub/lic/$f" ] && echo "  $f: $(wc -l < "$ART/pub/lic/$f") lines" || echo "  $f MISSING"; done

repack_tar() { # src inner out_name binaries... licname
    local src="$1" inner="$2" out="$3"; shift 3
    local all="$*"
    local binaries="${all% *}"          # everything but the last word
    local lic="${all##* }"              # the last word = the license file name
    local w="$ART/w-$(basename "$out" .tar.gz)"; rm -rf "$w"; mkdir -p "$w/$inner" "$w/x"
    try3 tar -xzf "$src" -C "$w/x" || { echo "  extract failed: $src"; return 1; }
    for b in $binaries; do
        local f; f="$(find "$w/x" -type f -name "$b" | head -1)"
        [ -n "$f" ] || { echo "  binary $b not in $(basename "$src")"; return 1; }
        [ "$(head -c 4 "$f" | od -A n -t x1 | tr -d ' ')" = "7f454c46" ] || { echo "  $b is NOT ELF"; return 1; }
        cp "$f" "$w/$inner/$b"; chmod 755 "$w/$inner/$b"
    done
    [ -s "$ART/pub/lic/$lic" ] && cp "$ART/pub/lic/$lic" "$w/$inner/LICENSE"
    ( cd "$w" && tar -czf "$ART/$out" "$inner" ); rm -rf "$w"
}
repack_gz() { # flat gz arch out_name binary inner lic
    local src="$1" arch="$2" out="$3" bin="$4" inner="$5" lic="$6"
    local w="$ART/w-$arch"; rm -rf "$w"; mkdir -p "$w/$inner"
    gunzip -c "$src" > "$w/$inner/$bin" || { echo "  gunzip failed"; return 1; }
    [ "$(head -c 4 "$w/$inner/$bin" | od -A n -t x1 | tr -d ' ')" = "7f454c46" ] || { echo "  $bin is NOT ELF"; return 1; }
    chmod 755 "$w/$inner/$bin"
    [ -s "$ART/pub/lic/$lic" ] && cp "$ART/pub/lic/$lic" "$w/$inner/LICENSE"
    ( cd "$w" && tar -czf "$ART/$out" "$inner" ); rm -rf "$w"
}
try3 repack_tar "$ART/frp_${FRVER}_linux_amd64.tar.gz" "frp_${FRVER}" "frp-$FRVER-linux-amd64.tar.gz" frps frpc LICENSE-frp.txt || exit 1
try3 repack_tar "$ART/frp_${FRVER}_linux_arm64.tar.gz" "frp_${FRVER}" "frp-$FRVER-linux-arm64.tar.gz" frps frpc LICENSE-frp.txt || exit 1
try3 repack_tar "$WS_AMD" "wstunnel_$WSVER" "wstunnel-$WSVER-linux-amd64.tar.gz" wstunnel LICENSE-wstunnel.txt || exit 1
try3 repack_tar "$WS_ARM" "wstunnel_$WSVER" "wstunnel-$WSVER-linux-arm64.tar.gz" wstunnel LICENSE-wstunnel.txt || exit 1
try3 repack_gz "$CH_AMD" amd64 "chisel-$CHVER-linux-amd64.tar.gz" chisel "chisel_$CHVER" "LICENSE-chisel.txt" || exit 1
try3 repack_gz "$CH_ARM" arm64 "chisel-$CHVER-linux-arm64.tar.gz" chisel "chisel_$CHVER" "LICENSE-chisel.txt" || exit 1
echo "  repacked 6 artifacts (ELF-verified)"

KEY=/tmp/eng45-signing.key
openssl genpkey -algorithm ed25519 -out "$KEY" 2>/dev/null
PUB_B64="$(openssl pkey -in "$KEY" -pubout -outform DER | base64 -w0)"
sign() { openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$1" -out "$1.sig" && base64 -w0 "$1.sig" > "$1.sig.b64" && sha256sum "$1" | awk '{print $1}' > "$1.sha"; }
for f in wstunnel-$WSVER-linux-amd64.tar.gz wstunnel-$WSVER-linux-arm64.tar.gz chisel-$CHVER-linux-amd64.tar.gz chisel-$CHVER-linux-arm64.tar.gz frp-$FRVER-linux-amd64.tar.gz frp-$FRVER-linux-arm64.tar.gz; do
    try3 sign "$ART/$f" || { echo "  sign failed: $f"; exit 1; }
done
echo "  signed 6 artifacts"
for e in wstunnel chisel frp; do
    for a in amd64 arm64; do
        n="$e-$([ $e = frp ] && echo $FRVER || { [ $e = wstunnel ] && echo $WSVER || echo $CHVER; })-linux-$a.tar.gz"
        try3 cp "$ART/$n" "$ART/pub/pk/api/agent/artifact/$n"
        try3 cp "$ART/$n" "$ART/pub/pk/api/agent/engine-artifacts/file/$n"
    done
done
{
    echo "PUB_B64=$PUB_B64"
    echo "WS_SHA_AMD=$(cat "$ART/wstunnel-$WSVER-linux-amd64.tar.gz.sha")"
    echo "WS_SIG_AMD=$(cat "$ART/wstunnel-$WSVER-linux-amd64.tar.gz.sig.b64")"
    echo "CH_SHA_AMD=$(cat "$ART/chisel-$CHVER-linux-amd64.tar.gz.sha")"
    echo "CH_SIG_AMD=$(cat "$ART/chisel-$CHVER-linux-amd64.tar.gz.sig.b64")"
    echo "FR_SHA_AMD=$(cat "$ART/frp-$FRVER-linux-amd64.tar.gz.sha")"
    echo "FR_SIG_AMD=$(cat "$ART/frp-$FRVER-linux-amd64.tar.gz.sig.b64")"
} > /var/tmp/eng45-env.sh
# host handoff: the small env file through /mnt/c (small writes are reliable)
cp /var/tmp/eng45-env.sh /mnt/c/Users/-Mahdi/Downloads/Quantum/01-REPOSITORIES/wt-p7-engines/tests/.eng45-env.sh && echo "  pins written"
