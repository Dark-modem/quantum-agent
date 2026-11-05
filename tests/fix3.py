p = "install-panel.sh"
s = open(p, encoding="utf-8").read()

# 1. tls_selfsigned_step function before credential_step definition
old_cred = "credential_step() {"
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
assert old_cred in s and "tls_selfsigned_step" not in s, "cred anchor"
s = s.replace(old_cred, new_cred, 1)

# 2. TLS_PORT/SERVER_NAME vars + flags
old_vars = 'NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0'
new_vars = 'NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0 TLS_PORT="7443" SERVER_NAME=""'
assert old_vars in s, "vars anchor"
s = s.replace(old_vars, new_vars)
old_flag = '        --port)           PORT="${2:-}"; shift 2;;'
new_flag = '''        --port)           PORT="${2:-}"; shift 2;;
        --tls-port)       TLS_PORT="${2:-}"; shift 2;;
        --server-name)    SERVER_NAME="${2:-}"; shift 2;;'''
assert old_flag in s, "flag anchor"
s = s.replace(old_flag, new_flag)
old_portchk = '[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port wants 1-65535"'
new_portchk = old_portchk + '''
[[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] && (( TLS_PORT >= 1 && TLS_PORT <= 65535 )) || die "--tls-port wants 1-65535"'''
assert old_portchk in s, "portchk anchor"
s = s.replace(old_portchk, new_portchk)

# 3. credential channel: info (not warn); die if capture fails
old_gen = '''        if [[ -n "$gen" ]]; then
            umask 077; printf '%s\\n' "$gen" > "$pwfile"; umask 022
            warn "generated admin password stored at $pwfile (mode 0600) — READ IT, then delete the file"
        fi'''
new_gen = '''        if [[ -n "$gen" ]]; then
            umask 077; printf '%s\\n' "$gen" > "$pwfile"; umask 022
            info "generated admin password stored at $pwfile (mode 0600) — READ IT, then delete the file"
        else
            die "could not capture the generated password (binary output changed)"
        fi'''
assert old_gen in s, "gen anchor"
s = s.replace(old_gen, new_gen)

# 4. python block: tls_port
old_py = '''u, port, base = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cfg.setdefault("username", u)
cfg.setdefault("port", port)
if base:
    cfg.setdefault("base_path", base.strip("/"))'''
new_py = '''u, port, tls_port, base = sys.argv[1], int(sys.argv[2]), int(sys.argv[4]), sys.argv[3]
cfg.setdefault("username", u)
cfg.setdefault("port", port)
cfg.setdefault("tls_port", tls_port)
if base:
    cfg.setdefault("base_path", base.strip("/"))'''
assert old_py in s, "py anchor"
s = s.replace(old_py, new_py)
old_pycall = 'GRE_PANEL_DIR="$PANEL_DIR" trun 20 python3 - "$USERNAME" "$PORT" "$BASE_PATH" <<\'PY\''
new_pycall = 'GRE_PANEL_DIR="$PANEL_DIR" trun 20 python3 - "$USERNAME" "$PORT" "$BASE_PATH" "$TLS_PORT" <<\'PY\''
assert old_pycall in s, "pycall anchor"
s = s.replace(old_pycall, new_pycall)

# 5. firewall: open TLS port
old_fw = '''    trun 30 ufw status 2>/dev/null | grep -q "${PORT}/tcp" && { info "panel port already allowed"; return 0; }
    trun 30 ufw allow "${PORT}/tcp" comment "quantum:installer:panel" >/dev/null
    info "panel port open: ${PORT}/tcp (tagged quantum:installer:panel)"'''
new_fw = '''    trun 30 ufw status 2>/dev/null | grep -q "${TLS_PORT}/tcp" && { info "panel HTTPS port already allowed"; return 0; }
    trun 30 ufw allow "${TLS_PORT}/tcp" comment "quantum:installer:panel" >/dev/null
    info "panel HTTPS port open: ${TLS_PORT}/tcp (tagged quantum:installer:panel)"'''
assert old_fw in s, "fw anchor"
s = s.replace(old_fw, new_fw)

# 6. verify probe on TLS port
old_v = 'if [[ $probe -eq 1 ]]; then info "panel port ${PORT} answers locally"; else warn "panel port ${PORT} does not answer yet"; ok=0; fi'
new_v = 'if [[ $probe -eq 1 ]]; then info "panel port ${TLS_PORT} answers locally"; else warn "panel port ${TLS_PORT} does not answer yet"; ok=0; fi'
assert old_v in s, "verify anchor"
s = s.replace(old_v, new_v)

# 7. final line
old_f = 'info "done. Login over https://<host>:${PORT}${BASE_PATH:+/${BASE_PATH#/}}/ — the panel is management-only;"'
new_f = 'info "done. Login over https://<host>:${TLS_PORT}${BASE_PATH:+/${BASE_PATH#/}}/ — the panel is management-only;"'
assert old_f in s, "final anchor"
s = s.replace(old_f, new_f)

open(p, "w", encoding="utf-8", newline="\n").write(s)
print("all panel HTTPS changes applied")
