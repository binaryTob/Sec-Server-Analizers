# Skill: IOC Hunting en Linux

## Objetivo
Caza de Indicators of Compromise (IOCs) implementando patrones por categoría (network, host, file, behavior). Producción de feeds de IOC formales que puedan ser compartidos y revistedos offline.

## Cuándo usarla
- Cualquier Compromise Assessment.
- Tras detectar un artefacto, pivot y buscar por toda la infraestructura.
- Mantenimiento de un threat feed interno (post-IR).

## Comandos

### IOCs Network Level
```bash
# All outgoing/ingoing IPs del día (extract de auth.log)
grep -hE "sshd|from " /var/log/auth.log* | \
  grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u

# DNS lookups
tcpdump -ni any 'port 53' -w dns.pcap -G 60 -W 24 -v   # capture DNS (post-incident)
resolv-conf  / cat /etc/resolv.conf
# Outbound DNS queries from journal:
journalctl -u systemd-resolved --since "1 day ago" | grep -E "Resolve\b" | head

# IP/reputation quick check (offline)
ripe-server: whois <IP>
```

### IOCs Host Level - procesos raros
```bash
# string matches en cmdline de todos los procesos vivos:
for p in /proc/[0-9]*/cmdline; do tr '\0' ' ' < $p 2>/dev/null | \
  grep -E 'wget http://|curl http://|/dev/tcp|/dev/udp|bash -i|nc -e|/tmp/.*sh|/dev/shm' && \
  echo "PID=$(dirname $p)"; done
# reverse shell patterns:
for p in /proc/[0-9]*/cmdline; do tr '\0' ' ' < $p 2>/dev/null | \
  grep -E 'exec 5<>/dev/tcp|exec 9<>/dev/tcp|nc.*-e|ncat.*-e|socat.*exec:|perl.*socket|python.*socket.*connect|/bin/sh -i|0<&111;1>&111'; done
```

### IOCs File Level
```bash
# Suspicious binaries executed from /tmp, /dev/shm, /var/tmp
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
ls -la /tmp/.X11 /tmp/.font-unix /tmp/.ICE-unix 2>/dev/null   # hidden dirs for stage
# Hidden dot-files in /root
ls -la /root/.[a-z]*
# Files with SUID/SGID set in last 30d
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -mtime -30 2>/dev/null
# Caza Malware list
find / -xdev 2>/dev/null \( -name 'Xorg.X*' -o -name 'kdevtmpfsi' -o -name 'kthreadd*' -o -name '*.so' -path '/usr/local/lib/*' \) | head -40
# Hashed contra threatfeed
sha256sum /usr/example/synthetic-miner 2>/dev/null
# Strings para wallet addresses:
grep -rE '4[A-Za-z0-9]{94}|8[A-Za-z0-9]{94}' /root /etc /var/log 2>/dev/null  # Monero addresses
grep -rE '0x[a-f0-9]{40}|bc1[q0-9][a-z0-9]{39,59}' /root /etc /var/log 2>/dev/null  # BTC/ETH
```

### IOCs Behavioral Level
```bash
# Comandos en bash_history sospechosos historial:
grep -hE "wget .*http://|curl .*http://|gcc.*\.c|chmod \+x|^cd /tmp|^cd /dev/shm|nc -[le]|/dev/tcp|useradd|usermod.*-a.*-G.*sudo|/etc/ld.so.preload|> /etc/ld.so.preload|echo /.*ld.so.preload" /root/.bash_history /home/*/.bash_history 2>/dev/null | head -50
# Descargas fromどこ http (no https) - flag:
grep -nE "http://[^']*\.(sh|c|so|x|13|64|bin|tar.gz)" /root/.bash_history /home/*/.bash_history 2>/dev/null
```

### Compiled binaries (from source)
```bash
# GCC activity history
grep -E "gcc |cc |make " /root/.bash_history /home/*/.bash_history 2>/dev/null
# DetectionRecently modified libs: /usr/local/lib shared objects created recently
find /usr/local/lib /usr/lib -name "*.so" -mtime -90 2>/dev/null
```

### Webshells (if web service)
```bash
# Common php webshells patterns
find /var/www /usr/share/nginx /opt -type f \( -name "*.php" -o -name "*.phtml" \) -mtime -90 2>/dev/null | \
  while read f; do
    if grep -qiE "eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress|convert_uudecode|\$_(POST|GET|REQUEST|COOKIE))" "$f"; then
      echo "SUSPECT: $f"; grep -nEi "eval\s*\(|base64_decode|\$_POST|\$_GET" "$f" | head
    fi
  done
# susptpicious jsp/py:
find /var/www /opt -type f \( -name "*.jsp" -o -name "*.jspx" -o -name "*.war" -o -name "cmd.py" \) 2>/dev/null
```

### Reverse shells, tunnels:
```bash
# Installed tools to check for:
which ncat socat chisel tmate frpc frp ligolo ngrok bore proxychains 2>/dev/null
ps -ef | grep -E 'chisel|tmate|frp|ligolo|ngrok|bore' | grep -v grep
# Listeners on uncommon ports:
ss -tulnp | awk '$5 !~ /:(80|443|22|8080|8443|53|9000)$/ {print}'
# Tunnels persisted:
ls /etc/systemd/system/*chisel* /etc/systemd/system/*tmate* /etc/systemd/system/*frp* 2>/dev/null
```

## Generación de feed estandarizado (STIX/OpenIOC)
```bash
# Extract IOCs en CSV
cat <<EOF > iocs.csv
type,value,context,first_seen,last_seen,confidence
ipv4-addr,203.0.113.99,xmrig pool,2026-08-04,2026-08-06,high
domain-name,example.invalid,malware delivery,2026-08-04,2026-08-06,high
file:sha256,0000000000000000000000000000000000000000000000000000000000000000,kthreadd64 (xmrig),2026-08-04,2026-08-06,high
x-mono-wallet,SYNTHETIC_WALLET_EXAMPLE,,2026-08-04,2026-08-06,high
email,synthetic@example.invalid,worker tag in pool,2026-08-04,2026-08-06,medium
user,synthetic-user,ssh comment proton mail,,,,needs_context
ipv4-addr,192.0.2.170,attacker source (AWS US-West),2026-08-04,2026-08-04,high
file:sha256,0000000000000000000000000000000000000000000000000000000000000000,ssh rsa pubkey fp initial access,,2026-08-04,high
EOF
```

## Falsos positivos
- `node /app/dist/main` (CI/CD streaming build).
- `python -c 'something'`, `ssh tunnel -L` de desarrolladores.
- `/dev/tcp` no es incompatible con esto en shell scripts legitimos (p.e. rootkit reverse poct).

## IOC list actual deste incident
```
IPs:
  192.0.2.170        (AWS US-West Oregon source attack Init, Aug 4 10:59 -03)
  203.0.113.99       (XMrig mining pool, port 143)
  192.0.2.245       (coincidental brute force IP)
  192.0.2.114        (brute-force bot)
  192.0.2.108        (brute-force bot)
  198.51.100.109        (brute-force bot)
  192.0.2.28        (brute-force bot)
  192.0.2.207          (brute-force bot)
  192.0.2.31       (brute-force bot)
  198.51.100.39        (brute-force bot)
  198.51.100.75        (brute-force bot)
Domains:
  example.invalid       (dropper/download delivery)
Files:
  /example/synthetic-dropper                 (sh dropper, 1729 bytes)
  /example/synthetic-downloader           (downloader)
  /example/synthetic-miner /usr/example/synthetic-miner     (XMRig, 8297712 bytes)
  /example/synthetic-library.so   (LD_PRELOAD userland rootkit, 16784 bytes)
  /etc/ld.so.preload → /example/synthetic-library.so
Hashes (SHA256):
  0000000000000000000000000000000000000000000000000000000000000000  kthreadd64
  (compute via item collected)
Wallet:
  SYNTHETIC_WALLET_EXAMPLE.worker55
Worker email:
  synthetic@example.invalid
Backdoor account:
  synthetic-user (UID 1005, GID 1006, password set Aug 4 2026 - old md5 ($1$) hash)
Persistence:
  /example/cron-entry (line: */5 * * * * root /example/synthetic-dropper 55)
  /etc/ld.so.preload -> synthetic-library.so
  ldap user synthetic-user → group sudo
TTP ATT&CK:
  T1110 (brute force), T1078 (Valid Accounts), T1098.001 (SSH key add), T1136.001 (Create synthetic-user),
  T1059.004 (bash), T1105 (Ingress Tool Transfer wget), T1027.002 (compile .c → .so),
  T1547.007 (ld.so.preload), T1543.002 (systemd cron timer - certbot cron), T1053.003 (cron),
  T1496 (Resource Hijack - XMRig), T1571 (Non-Standard Port - 143), T1572 (TACAC protocol filters),
  T1070.002/004 (Clear logs (potentially truncated)), T1562.006 (auditd doesn't run).
```

## Buenas prácticas
- Caza automatizada: instalar Wazuh agent (or host-based IOC engine) checkando contra feed MISP.
- Cron un script egress IP去 known-bad (extract from MISP) → firewall-deny.
- Sube cada artifactos IOCs (wallet, shipdomains) a MISP para community Intel.
- Update YARA rules (clonar `YARA-Rules/rules` repo).
- Maintain a CSV/STIX feed versionado git local del equipo IR.
- Suscribirse a CISA alerts, abuse.ch, MalwareBazaar, MISP default feeds.

## Referencias
- MITRE ATT&CK.
- STIX 2.1 spec.
- OpenIOC format - Mandiant.
- abuse.ch Threatfox (https://threatfox.abuse.ch).
- MISP - https://www.misp-project.org/.
- YARA + Loki Scanner (https://github.com/Neo23x0/Loki).
- AlienVault OTX.
- Strangereal Intel "perfctl" writeup.