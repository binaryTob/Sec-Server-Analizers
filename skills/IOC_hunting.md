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
sha256sum /usr/sbin/kthreadd64 2>/dev/null
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
ipv4-addr,89.117.109.224,xmrig pool,2026-08-04,2026-08-06,high
domain-name,localhost0.xyz,malware delivery,2026-08-04,2026-08-06,high
file:sha256,b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d,kthreadd64 (xmrig),2026-08-04,2026-08-06,high
x-mono-wallet,4B7vsy8ccUwQufiyMN9jgoDphPUDzGUvBhE4f19U5z3WMPZqx2gjHrv2PxpuBSZRHAdD5qfEnPiApdFk4fhHZGVwU1YG1L2,,2026-08-04,2026-08-06,high
email,sarapena7979@gmail.com,worker tag in pool,2026-08-04,2026-08-06,medium
user,4h1g4L0w4,ssh comment proton mail,,,,needs_context
ipv4-addr,54.193.29.177,attacker source (AWS US-West),2026-08-04,2026-08-04,high
file:sha256,nz1L6wKzffgO0NumXgcS51pUaAQAYmA0rqDpKvqCfaU,ssh rsa pubkey fp initial access,,2026-08-04,high
EOF
```

## Falsos positivos
- `node /app/dist/main` (CI/CD streaming build).
- `python -c 'something'`, `ssh tunnel -L` de desarrolladores.
- `/dev/tcp` no es incompatible con esto en shell scripts legitimos (p.e. rootkit reverse poct).

## IOC list actual deste incident
```
IPs:
  54.193.29.177        (AWS US-West Oregon source attack Init, Aug 4 10:59 -03)
  89.117.109.224       (XMrig mining pool, port 143)
  103.243.26.174       (coincidental brute force IP)
  45.148.10.157        (brute-force bot)
  45.148.10.151        (brute-force bot)
  45.148.10.152        (brute-force bot)
  45.225.135.21        (brute-force bot)
  15.204.8.16          (brute-force bot)
  181.188.148.74       (brute-force bot)
  125.16.27.190        (brute-force bot)
  187.120.189.6        (brute-force bot)
Domains:
  localhost0.xyz       (dropper/download delivery)
Files:
  /sbin/Xorg.X13                 (sh dropper, 1729 bytes)
  /sbin/busybox.static           (downloader)
  /sbin/kthreadd64 /usr/sbin/kthreadd64     (XMRig, 8297712 bytes)
  /usr/local/lib/kthreadd32.so   (LD_PRELOAD userland rootkit, 16784 bytes)
  /etc/ld.so.preload → /usr/local/lib/kthreadd32.so
Hashes (SHA256):
  b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d  kthreadd64
  (compute via item collected)
Wallet:
  4B7vsy8ccUwQufiyMN9jgoDphPUDzGUvBhE4f19U5z3WMPZqx2gjHrv2PxpuBSZRHAdD5qfEnPiApdFk4fhHZGVwU1YG1L2.worker55
Worker email:
  sarapena7979@gmail.com
Backdoor account:
  rpcd (UID 1005, GID 1006, password set Aug 4 2026 - old md5 ($1$) hash)
Persistence:
  /etc/cron.d/certbot (line: */5 * * * * root /sbin/Xorg.X13 55)
  /etc/ld.so.preload -> kthreadd32.so
  ldap user rpcd → group sudo
TTP ATT&CK:
  T1110 (brute force), T1078 (Valid Accounts), T1098.001 (SSH key add), T1136.001 (Create rpcd),
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