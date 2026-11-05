p = "install-panel.sh"
s = open(p, encoding="utf-8").read()
applied = []

if "tls_selfsigned_step() {" not in s:
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
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "${td}/server.key" -out "${td}/server.crt" \
        -subj "/CN=${cn}" >/dev/null 2>&1
    chmod 600 "${td}/server.key"; chmod 644 "${td}/server.crt"
    info "self-signed TLS certificate generated (${td}) — panel serves HTTPS on :${TLS_PORT}"
}

credential_step() {'''
    assert old_cred in s, "cred anchor"
    s = s.replace(old_cred, new_cred, 1)
    applied.append("tls fn")

if 'TLS_PORT="7443"' not in s:
    old_vars = 'NO_START=0 CHECK_ONLY=0 VERIFY_ONLY=0'
    assert old_vars in s, "vars anchor"
    s = s.replace(old_vars, old_vars + ' TLS_PORT="7443" SERVER_NAME=""')
    applied.append("vars")

old_flag = '        --port)           PORT="${2:-}"; shift 2;;'
if '--tls-port)' not in s:
    assert old_flag in s, "flag anchor"
    s = s.replace(old_flag, old_flag + '''
        --tls-port)       TLS_PORT="${2:-}"; shift 2;;
        --server-name)    SERVER_NAME="${2:-}"; shift 2;;''')
    applied.append("flags")

old_portchk = '[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port wants 1-65535"'
if '--tls-port wants' not in s:
    assert old_portchk in s, "portchk anchor"
    s = s.replace(old_portchk, old_portchk + '''
[[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] && (( TLS_PORT >= 1 && TLS_PORT <= 65535 )) || die "--tls-port wants 1-65535"''')
    applied.append("portchk")

old_gen = '''            umask 077; printf '%s\n' "$gen" > "$pwfile"; umask 022
            warn "generated admin password stored at $pwfile (mode 0600) — READ IT, then delete the file"
        fi'''
if "READ IT, then delete the file" in s and 'info "generated admin password' not in s:
    new_gen = '''            umask 077; printf '%s\n' "$gen" > "$pwfile"; umask 022
            info "generated admin password stored at $pwfile (mode 0600) — READ IT, then delete the file"
        else
            die "could not capture the generated password (binary output changed)"
        fi'''
    assert old_gen in s, "gen anchor"
    s = s.replace(old_gen, new_gen)
    applied.append("cred channel")

old_py = '''u, port, base = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cfg.setdefault("username", u)
cfg.setdefault("port", port)
if base:
    cfg.setdefault("base_path", base.strip("/"))'''
if "tls_port, base" not in s:
    assert old_py in s, "py anchor"
    s = s.replace(old_py, '''u, port, tls_port, base = sys.argv[1], int(sys.argv[2]), int(sys.argv[4]), sys.argv[3]
cfg.setdefault("username", u)
cfg.setdefault("port", port)
cfg.setdefault("tls_port", tls_port)
if base:
    cfg.setdefault("base_path", base.strip("/"))''')
    old_pycall = 'trun 20 python3 - "$USERNAME" "$PORT" "$BASE_PATH" <<\'PY\''
    assert old_pycall in s, "pycall anchor"
    s = s.replace(old_pycall, 'trun 20 python3 - "$USERNAME" "$PORT" "$BASE_PATH" "$TLS_PORT" <<\'PY\'')
    applied.append("py tls_port")

old_fw = '''    trun 30 ufw status 2>/dev/null | grep -q "${PORT}/tcp" && { info "panel port already allowed"; return 0; }
    trun 30 ufw allow "${PORT}/tcp" comment "quantum:installer:panel" >/dev/null
    info "panel port open: ${PORT}/tcp (tagged quantum:installer:panel)"'''
if "panel HTTPS port open" not in s:
    assert old_fw in s, "fw anchor"
    s = s.replace(old_fw, '''    trun 30 ufw status 2>/dev/null | grep -q "${TLS_PORT}/tcp" && { info "panel HTTPS port already allowed"; return 0; }
    trun 30 ufw allow "${TLS_PORT}/tcp" comment "quantum:installer:panel" >/dev/null
    info "panel HTTPS port open: ${TLS_PORT}/tcp (tagged quantum:installer:panel)"''')
    applied.append("fw")

old_v = 'if [[ $probe -eq 1 ]]; then info "panel port ${PORT} answers locally"; else warn "panel port ${PORT} does not answer yet"; ok=0; fi'
if "${TLS_PORT} answers locally" not in s:
    assert old_v in s, "verify anchor"
    s = s.replace(old_v, 'if [[ $probe -eq 1 ]]; then info "panel port ${TLS_PORT} answers locally"; else warn "panel port ${TLS_PORT} does not answer yet"; ok=0; fi')
    applied.append("verify probe")

old_f = 'info "done. Login over https://<host>:${PORT}${BASE_PATH:+/${BASE_PATH#/}}/ — the panel is management-only;"'
if "Login over https://<host>:${TLS_PORT}" not in s:
    assert old_f in s, "final anchor"
    s = s.replace(old_f, 'info "done. Login over https://<host>:${TLS_PORT}${BASE_PATH:+/${BASE_PATH#/}}/ — the panel is management-only;"')
    applied.append("final url")

open(p, "w", encoding="utf-8", newline="\n").write(s)
print("applied:", applied or "none needed")
