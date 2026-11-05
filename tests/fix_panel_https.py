# fix_panel_https.py — panel installer robustness (lab findings):
#   1. HTTPS (self-signed) from the FIRST start: generate the cert into
#      <PANEL_DIR>/tls/server.{crt,key} before the service starts (the panel
#      serves it automatically on TLSPort 7443 via startHTTPSListener).
#   2. The generated password goes ONLY to the 0600 file — never stdout,
#      never the audit log (the binary's own printout is captured and
#      suppressed already; make that guarantee explicit).
#   3. The unit gets the panel HTTPS port opened in the firewall step
#      instead of plaintext 8000 assumptions.

p = "install-panel.sh"
s = open(p, encoding="utf-8").read()

# --- 1. HTTPS cert generation step, inserted before credential_step in main
old_main_seq = '''install_binary
create_user
credential_step
write_unit'''
new_main_seq = '''install_binary
create_user
tls_selfsigned_step
credential_step
write_unit'''
assert old_main_seq in s, "main sequence anchor missing"
s = s.replace(old_main_seq, new_main_seq)

# --- 2. the step itself (inserted before credential_step definition)
old_cred = '''credential_step() {'''
new_cred = '''tls_selfsigned_step() {
    # HTTPS from the FIRST start: the panel serves <configDir>/tls/server.crt
    # + server.key on TLSPort (default 7443) via startHTTPSListener. Without
    # a cert it would only bind localhost HTTP (upstream behavior).
    local td="${PANEL_DIR}/tls"
    if [[ -s "${td}/server.crt" && -s "${td}/server.key" ]]; then
        info "TLS certificate already present (${td})"
        return 0
    fi
    mkdir -p "$td"; chmod 700 "$td"
    local cn="quantum-panel"
    [[ -n "$SERVER_NAME" ]] && cn="$SERVER_NAME"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \\
        -keyout "${td}/server.key" -out "${td}/server.crt" \\
        -subj "/CN=${cn}" >/dev/null 2>&1
    chmod 600 "${td}/server.key"; chmod 644 "${td}/server.crt"
    info "self-signed TLS certificate generated (${td}) — panel serves HTTPS on :${TLS_PORT}"
}

credential_step() {'''
assert old_cred in s
s = s.replace(old_cred, new_cred, 1)

# --- 3. TLS_PORT variable + SERVER_NAME in args/defaults
s = s.replace('NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0',
              'NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0 TLS_PORT="7443" SERVER_NAME=""')
s = s.replace('        --port)           PORT="${2:-}"; shift 2;;',
              '        --port)           PORT="${2:-}"; shift 2;;\n'
              '        --tls-port)       TLS_PORT="${2:-}"; shift 2;;\n'
              '        --server-name)    SERVER_NAME="${2:-}"; shift 2;;')
s = s.replace('[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port wants 1-65535"',
              '[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port wants 1-65535"\n'
              '[[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] && (( TLS_PORT >= 1 && TLS_PORT <= 65535 )) || die "--tls-port wants 1-65535"')

# --- 4. credential_step: password NEVER on stdout; 0600 file is the only
#        channel. Also set tls_port in panel.json via the python block.
s = s.replace('''        local gen
        gen="$(printf '%s\\n' "$out" | awk '/^Password:/{print $2}')"
        if [[ -n "$gen" ]]; then
            umask 077; printf '%s\\n' "$gen" > "$pwfile"; umask 022
            warn "generated admin password stored at $pwfile (mode 0600) — READ IT, then delete the file"
        fi''',
'''        local gen
        gen="$(printf '%s\\n' "$out" | awk '/^Password:/{print $2}')"
        if [[ -n "$gen" ]]; then
            umask 077; printf '%s\\n' "$gen" > "$pwfile"; umask 022
            info "generated admin password stored at $pwfile (mode 0600) — READ IT, then delete the file"
        else
            die "could not capture the generated password (binary output changed)"
        fi''')

# --- 5. python block: also setdefault tls_port
s = s.replace('''u, port, base = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cfg.setdefault("username", u)
cfg.setdefault("port", port)
if base:
    cfg.setdefault("base_path", base.strip("/"))''',
'''u, port, tls_port, base = sys.argv[1], int(sys.argv[2]), int(sys.argv[4]), sys.argv[3]
cfg.setdefault("username", u)
cfg.setdefault("port", port)
cfg.setdefault("tls_port", tls_port)
if base:
    cfg.setdefault("base_path", base.strip("/"))''')
s = s.replace('GRE_PANEL_DIR="$PANEL_DIR" trun 20 python3 - "$USERNAME" "$PORT" "$BASE_PATH" <<\'PY\'',
              'GRE_PANEL_DIR="$PANEL_DIR" trun 20 python3 - "$USERNAME" "$PORT" "$BASE_PATH" "$TLS_PORT" <<\'PY\'')

# --- 6. firewall: open the HTTPS (tls) port, tagged; keep 8000 untouched
s = s.replace('''    trun 30 ufw status 2>/dev/null | grep -q "${PORT}/tcp" && { info "panel port already allowed"; return 0; }
    trun 30 ufw allow "${PORT}/tcp" comment "quantum:installer:panel" >/dev/null
    info "panel port open: ${PORT}/tcp (tagged quantum:installer:panel)"''',
'''    trun 30 ufw status 2>/dev/null | grep -q "${TLS_PORT}/tcp" && { info "panel HTTPS port already allowed"; return 0; }
    trun 30 ufw allow "${TLS_PORT}/tcp" comment "quantum:installer:panel" >/dev/null
    info "panel HTTPS port open: ${TLS_PORT}/tcp (tagged quantum:installer:panel)"''')

# --- 7. verify(): probe the TLS port, not the plaintext one
s = s.replace('''    if [[ $probe -eq 1 ]]; then info "panel port ${PORT} answers locally"; else warn "panel port ${PORT} does not answer yet"; ok=0; fi''',
'''    if [[ $probe -eq 1 ]]; then info "panel port ${TLS_PORT} answers locally"; else warn "panel port ${TLS_PORT} does not answer yet"; ok=0; fi''')

# --- 8. final info line: https URL
s = s.replace('''info "done. Login over https://<host>:${PORT}${BASE_PATH:+/${BASE_PATH#/}}/ — the panel is management-only;"''',
'''info "done. Login over https://<host>:${TLS_PORT}${BASE_PATH:+/${BASE_PATH#/}}/ — the panel is management-only;"''')

open(p, "w", encoding="utf-8", newline="\n").write(s)
print("panel installer: HTTPS-from-first-start + credential channel hardened")
