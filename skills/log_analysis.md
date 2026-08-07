---
id: "log_analysis"
name: "Skill: Log Analysis en Linux"
version: "2.0"
category: "analysis"
phase: "ident"
risk: "readonly"
execution_mode: "auto"
depends_on: []
provides: ["incident_response", "ssh_forensics", "persistence_detection"]
triggers:
  - "Compromise Assessment (correlación de eventos basada en tiempo)"
  - "Investigación de un incidente específico (login, comando sospechoso)"
  - "Revisión de intentos de brute force SSH"
  - "Detección de gap temporal en logs (posible tampering)"
mitre_attack:
  - "T1070.002"  # Clear Linux/Mac System Logs
  - "T1562.006"  # auditd bypass
  - "T1078"      # Valid Accounts
  - "T1136.001"  # Create Account
  - "T1548.003"  # sudo
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar extractos de logs"
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
  UNTIL:
    type: "datetime"
    default: "now"
    required: false
  TARGET_USER:
    type: "string"
    required: false
    description: "Filtrar eventos de autenticación para un usuario específico"
  SUSPECT_IP:
    type: "string"
    required: false
    description: "Filtrar eventos por IP de origen sospechosa"
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "ipv4-addr"
    value: "54.193.29.177"
    context: "IP origen atacante — root login via SSH key"
    confidence: "high"
  - type: "event"
    value: "useradd rpcd"
    context: "Creación de usuario backdoor en auth.log"
    confidence: "high"
---

# Skill: Log Analysis en Linux

## Objetivo
Analizar logs del sistema (auth.log, syslog, journalctl, kern, cron, wtmp, btmp) para detectar evidencia de intrusión inicial, movimiento lateral, creación de persistencia, escalación de privilegios (sudo, su), logins sospechosos y posible tampering de logs.

## Cuándo usarla
- Compromise Assessment: correlación de eventos basada en tiempo.
- Investigación de un incidente específico (login, comando sospechoso).
- Revisión de intentos de brute force SSH.
- Detección de gaps en logs (posible anti-forense).

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de salida |
| `{{SINCE}}` | datetime | no | `1 day ago` | Inicio de ventana temporal |
| `{{UNTIL}}` | datetime | no | `now` | Fin de ventana temporal |
| `{{TARGET_USER}}` | string | no | — | Usuario específico a investigar |
| `{{SUSPECT_IP}}` | string | no | — | IP sospechosa a rastrear |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"/{auth,sudo,cron,journal,system}
echo "LOG ANALYSIS START: $(date -Iseconds)" | tee "{{OUTPUT_DIR}}/manifest.txt"
```

## Comandos

### 1. /var/log — inventario de archivos de log clásicos
```bash
# [risk:ro] [mode:auto]
{
  echo "=== LOG FILES INVENTORY ==="
  ls -la /var/log/
  echo "=== AUTH LOG FILES ==="
  ls -la /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.*.gz 2>/dev/null
  echo "=== SYSLOG FILES ==="
  ls -la /var/log/syslog /var/log/syslog.* /var/log/messages /var/log/kern.log 2>/dev/null
  echo "=== BINARY LOGS ==="
  ls -la /var/log/audit/ /var/log/wtmp /var/log/btmp /var/log/faillog 2>/dev/null
  echo "=== COMPRESSED AUTH LOGS ==="
  zcat /var/log/auth.log.2.gz 2>/dev/null | grep -E "Accepted|Failed" | head -20
  zgrep -E "Invalid user" /var/log/auth.log.2.gz 2>/dev/null | head -20
} | tee "{{OUTPUT_DIR}}/log_inventory.txt"
```

### 2. auth.log — sesiones exitosas, sudo y creación de usuarios
```bash
# [risk:ro] [mode:auto]
{
  echo "=== ACCEPTED LOGINS ==="
  grep -hE "Accepted" /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.*.gz 2>/dev/null
  echo "=== ACCEPTED BY METHOD + FINGERPRINT ==="
  grep -hE "Accepted (publickey|password|keyboard-interactive)" /var/log/auth.log* 2>/dev/null | \
    sed -nE 's/.*Accepted ([^ ]+ [^ ]+) for ([^ ]+) from ([^ ]+) port.*: (SHA256:[^ ]+).*/\1 \2 from=\3 fp=\4/p' | \
    sort | uniq -c | sort -nr
  echo "=== USER CREATION/MODIFICATION ==="
  grep -hE "useradd|usermod|chpasswd|passwd.*changed.*uid|gshadow" /var/log/auth.log* 2>/dev/null
  echo "=== SUDO COMMANDS ==="
  grep -hE "sudo:" /var/log/auth.log* 2>/dev/null
  echo "=== PAM SESSIONS ==="
  grep -hE "pam_unix\((sshd|sudo|su|cron):session\): session (opened|closed)" /var/log/auth.log* 2>/dev/null
} | tee "{{OUTPUT_DIR}}/auth/auth_events.txt"
```

### 3. sudo log — comandos ejecutados con privilegios
```bash
# [risk:ro] [mode:auto]
grep -hE "sudo:[ ]+.*TTY=" /var/log/auth.log* 2>/dev/null \
  | tee "{{OUTPUT_DIR}}/sudo/sudo_commands.txt"
```

### 4. Cron log
```bash
# [risk:ro] [mode:auto]
{
  echo "=== CRON IN SYSLOG ==="
  grep -i cron /var/log/syslog /var/log/syslog.1 2>/dev/null | tail -50
  echo "=== CRON LOG (dedicated) ==="
  cat /var/log/cron.log /var/log/cron 2>/dev/null | tail -50
} | tee "{{OUTPUT_DIR}}/cron/cron_events.txt"
```

### 5. Journalctl (systemd journal)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== FULL JOURNAL (${{SINCE}} → ${{UNTIL}}) ==="
  journalctl --since "{{SINCE}}" --until "{{UNTIL}}" 2>/dev/null
  echo "=== SSH UNIT ==="
  journalctl -u ssh --since "{{SINCE}}" 2>/dev/null
  echo "=== CRON UNIT ==="
  journalctl -u cron --since "{{SINCE}}" 2>/dev/null
  echo "=== AUTH FACILITY ==="
  journalctl --facility auth --since "{{SINCE}}" 2>/dev/null | tail -50
  echo "=== KERNEL LOG ==="
  journalctl -k --since "1 hour ago" 2>/dev/null
  echo "=== SSHD (by identifier) ==="
  journalctl -t sshd --since "{{SINCE}}" 2>/dev/null
} | tee "{{OUTPUT_DIR}}/journal/journal_full.txt"
```

### 6. Logs de kernel y sistema
```bash
# [risk:ro] [mode:auto]
{
  echo "=== ERROR LEVEL ==="
  journalctl --since "{{SINCE}}" -p err 2>/dev/null
  echo "=== OOM/PANIC/SEGFAULT ==="
  grep -iE "oom|kill|panic|segfault|Hung task" /var/log/kern.log /var/log/syslog 2>/dev/null | tail -30
  echo "=== DMESG ==="
  dmesg -wT 2>/dev/null | tail -30
  echo "=== LAST (wtmp) ==="
  last -F
  echo "=== LASTB (btmp) ==="
  lastb -F
  echo "=== LASTLOG ==="
  lastlog 2>/dev/null
} | tee "{{OUTPUT_DIR}}/system/system_events.txt"

# Auditd (si está disponible)
{
  echo "=== AUSEARCH LOGIN ==="
  ausearch -m user_login -ts "{{SINCE}}" 2>/dev/null
  echo "=== AUREPORT AUTH ==="
  aureport -au 2>/dev/null
  echo "=== AUREPORT EXEC ==="
  aureport -x 2>/dev/null
  echo "=== AUREPORT USER SUMMARY ==="
  aureport -u -i --summary 2>/dev/null
} | tee "{{OUTPUT_DIR}}/system/auditd.txt"
```

### 7. Búsqueda focalizada por usuario o IP
```bash
# [risk:ro] [mode:auto]
# Solo si se proporciona TARGET_USER
if [ -n "{{TARGET_USER}}" ]; then
  echo "=== EVENTS FOR USER: {{TARGET_USER}} ==="
  grep -hE "{{TARGET_USER}}" /var/log/auth.log* 2>/dev/null | head -50
fi

# Solo si se proporciona SUSPECT_IP
if [ -n "{{SUSPECT_IP}}" ]; then
  echo "=== EVENTS FROM IP: {{SUSPECT_IP}} ==="
  grep -hE "from {{SUSPECT_IP}}" /var/log/auth.log* 2>/dev/null | head -50
fi
```

<!-- MODULE:helpers.collect_auth_logs -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- `Accepted publickey for root from <IP> ssh2: RSA SHA256:<fp>` → root ingresó con llave SSH. Notar hora: suele ser el vector inicial del atacante.
- `useradd[...]: new user: name=rpcd, ...` → el atacante creó un usuario (implica que ya tenía root).
- `Accepted keyboard-interactive/pam for rpcd from <IP>` → el atacante ingresa con el usuario backdoor recién creado.
- `sudo: rpcd : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/su` → escalación de privilegios vía sudo desde el backdoor.
- `last -F` y `lastb -F` → wtmp/btmp trackean logins exitosos/fallidos (rotación ~6 meses default).
- "message repeated N times" en auth.log → compresión de rsyslog para eventos repetidos.
- journalctl `-u docker` puede mostrar eventos anómalos de containers (creación, eliminación, stdin attach).

### Indicadores de tampering de logs
- Gaps de fechas en auth.log: el atacante truncó `/var/log/auth.log`.
- Líneas faltantes entre rotaciones de log (horas/días sin eventos cuando debería haber).
- `journalctl --verify` detecta corrupciones del journal.
- Verificar tamaños: `ls -l /var/log/auth.log*` — gaps grandes = posible eliminación.
- `last -F` y `wtmp`: verificar integridad de `/var/log/wtmp`.

## Falsos positivos
- Brute force desde bots contra root (`Failed password for root from ...`): ruido normal de internet. Foco en `Accepted`.
- `systemd-networkd` reportado por chkrootkit como "sniffer": legítimo.
- `session opened for cron`: cada script cron genera esta entrada. NO es sesión de atacante.
- `lastb` con fallos de bots no asociados a cuentas reales.

## IOC específicos en logs
- root login desde IPs de cloud/foreign (54.193.*, 45.10.*, 138.2.*).
- `useradd` + `usermod -aG sudo` → creación de cuentas backdoor.
- `sudo: ... COMMAND=/usr/bin/su` desde usuario no-admin → escalación.
- Comandos `wget http://localhost0.xyz`, `gcc`, `chmod +x` agrupados temporalmente con creación de usuario.
- Logs truncados en rango temporal específico (anti-forense).

## Buenas prácticas
- Configurar syslog remoto / SIEM: rsyslog forward (`/etc/rsyslog.d/99-remote.conf`: `*.* @@remote:514`).
- Journal persistente: `mkdir /var/log/journal && systemctl restart systemd-journal-flush`.
- Reglas auditd para puntos críticos:
  ```
  auditctl -w /var/log/auth.log -p wa -k authlog
  auditctl -w /etc/cron.d -p wa -k crond
  ```
- `logrotate` con compresión y retención: `rotate 52 weekly compress delaycompress`.
- Mantener `wtmp` y `btmp` — nunca borrar, son críticos para timeline.
- Monitorizar cambios en archivos de log con AIDE o auditd watch.

## Referencias
- `man 5 wtmp`, `man 5 btmp`, `man 5 lastlog`, `man 5 utmp`
- `/etc/rsyslog.conf` y `/etc/rsyslog.d/`
- journald binary format: `/var/log/journal`
- auditd rules: `/usr/share/doc/audit-2.x/rules/10-base-config.rules`
- MITRE ATT&CK: T1070.002, T1562.006
- SANS DFIR 504: "Linux Log Analysis"
