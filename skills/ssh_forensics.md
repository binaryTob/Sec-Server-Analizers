---
id: "ssh_forensics"
name: "Skill: SSH Forensics"
version: "2.0"
category: "forensics"
phase: "ident"
risk: "readonly"
execution_mode: "auto"
depends_on: ["log_analysis"]
provides: ["incident_response", "persistence_detection"]
triggers:
  - "Compromise Assessment (el vector inicial en Linux suele ser SSH)"
  - "Detección de nuevas llaves en authorized_keys o logins desde IPs foráneas"
  - "Auditoría de hardening de configuración SSH"
mitre_attack:
  - "T1078"      # Valid Accounts
  - "T1110"      # Brute Force
  - "T1098"      # Account Manipulation
  - "T1136"      # Create Account
  - "T1021.004"  # Remote Services: SSH
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar evidencia SSH"
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
  BASELINE_DATE:
    type: "string"
    required: false
    description: "Fecha del baseline anterior de authorized_keys (para diff)"
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "ssh-fingerprint"
    value: "SHA256:nz1L6wKzffgO0NumXgcS51pUaAQAYmA0rqDpKvqCfaU"
    context: "RSA pubkey fingerprint — vector inicial"
    confidence: "high"
  - type: "ipv4-addr"
    value: "54.193.29.177"
    context: "IP origen atacante SSH (AWS US-West)"
    confidence: "high"
  - type: "user"
    value: "rpcd"
    context: "Usuario backdoor con login keyboard-interactive"
    confidence: "high"
---

# Skill: SSH Forensics

## Objetivo
Investigar evidencia forense asociada a SSH en un host Linux: llaves autorizadas, configuración de sshd, logs de autenticación (Accept por password, publickey, source IPs). Detectar el login inicial del atacante, llaves maliciosas y backdoors vía SSH.

## Cuándo usarla
- Compromise Assessment (el vector inicial en hosts Linux suele ser SSH).
- Detectar nuevas llaves en authorized_keys o logins desde IPs foráneas.
- Auditoría de hardening de configuración SSH.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de salida |
| `{{SINCE}}` | datetime | no | `1 day ago` | Ventana temporal |
| `{{BASELINE_DATE}}` | string | no | — | Fecha del baseline anterior de authorized_keys |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"/{keys,config,logs}
```

## Comandos

### 1. Lectura de authorized_keys (T1078 / T1098)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== ROOT AUTHORIZED_KEYS ==="
  ls -la /root/.ssh/ 2>/dev/null
  cat -n /root/.ssh/authorized_keys 2>/dev/null
  echo "=== FINGERPRINTS ==="
  ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null
  echo "=== ACTIVE KEYS ONLY (no comments) ==="
  grep -vE '^#|^$' /root/.ssh/authorized_keys 2>/dev/null | awk '{print $1,$3}'
  echo "=== AUTHORIZED_KEYS BACKUPS ==="
  ls -la /root/.ssh/authorized_keys* 2>/dev/null
  echo "=== FINGERPRINTS FROM BACKUPS ==="
  for f in /root/.ssh/authorized_keys.*; do
    [ -f "$f" ] && echo "### $f" && ssh-keygen -lf "$f" 2>/dev/null
  done
} | tee "{{OUTPUT_DIR}}/keys/authorized_keys_analysis.txt"

# Diff contra baseline (si se proporciona)
if [ -n "{{BASELINE_DATE}}" ]; then
  diff "/root/.ssh/authorized_keys.{{BASELINE_DATE}}" /root/.ssh/authorized_keys 2>/dev/null \
    | tee "{{OUTPUT_DIR}}/keys/authorized_keys_diff.txt"
fi
```

### 2. Usuarios con authorized_keys
```bash
# [risk:ro] [mode:auto]
for u in $(awk -F: '$7 ~ /(bash|sh)$/ {print $1}' /etc/passwd); do
  H=$(eval echo "~$u")
  if [ -f "$H/.ssh/authorized_keys" ]; then
    echo "### $u -> $H/.ssh/authorized_keys"
    cat "$H/.ssh/authorized_keys"
    ssh-keygen -lf "$H/.ssh/authorized_keys" 2>/dev/null
    echo "---"
  fi
done | tee "{{OUTPUT_DIR}}/keys/all_users_authorized_keys.txt"
```

### 3. sshd config — auditoría completa
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SSHD_CONFIG ==="
  cat /etc/ssh/sshd_config
  echo "=== SSHD_CONFIG.D ==="
  ls -la /etc/ssh/sshd_config.d/ 2>/dev/null
  for f in /etc/ssh/sshd_config.d/*; do
    [ -f "$f" ] && echo "### $f" && cat "$f"
  done
  echo "=== EFFECTIVE RUNTIME CONFIG ==="
  sshd -T 2>/dev/null
  echo "=== KEY SECURITY PARAMS ==="
  grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractive|AllowUsers|AllowGroups|Match|AuthorizedKeysFile|PermitEmptyPasswords|X11Forwarding|AllowTcpForwarding|PermitTunnel)" \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
  echo "=== HOST KEYS ==="
  ls -la /etc/ssh/ssh_host_* 2>/dev/null
  echo "=== SSH CERTIFICATES (CA) ==="
  ls -la /etc/ssh/ssh_ca.pub /etc/ssh/auth_principals 2>/dev/null
} | tee "{{OUTPUT_DIR}}/config/sshd_config_audit.txt"
```

### 4. Logs de autenticación SSH
```bash
# [risk:ro] [mode:auto]
{
  echo "=== AUTH EVENTS (no repeated) ==="
  grep -hE "Accepted|Failed|Invalid|Disconnected|useradd|usermod|sudo.*:" \
    /var/log/auth.log /var/log/auth.log.1 2>/dev/null | grep -v repeated
  echo "=== SOURCE IPs BY FREQUENCY ==="
  grep -hE "Accepted (publickey|password|keyboard-interactive)" \
    /var/log/auth.log /var/log/auth.log.1 2>/dev/null | \
    awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | sort | uniq -c | sort -nr | head -20
  echo "=== FINGERPRINTS BY FREQUENCY ==="
  grep -hE "Accepted publickey" /var/log/auth.log /var/log/auth.log.1 2>/dev/null | \
    sed -n 's/.*SHA256:\([A-Za-z0-9/+]*\).*/SHA256:\1/p' | sort | uniq -c
  echo "=== ROOT SUCCESSFUL LOGINS ==="
  grep -hE "Accepted (publickey|password|keyboard-interactive/pam) for root" \
    /var/log/auth.log /var/log/auth.log.1 2>/dev/null
  echo "=== SESSIONS BY USER + IP ==="
  last -F | awk '$1!="reboot"{print $1,$3}' | sort | uniq -c | sort -nr
  echo "=== ROOT LOGIN IPs ==="
  last -F | awk '$1=="root"{print $3}' | sort | uniq -c
  echo "=== FAILED LOGINS ==="
  lastb -F | head -50
} | tee "{{OUTPUT_DIR}}/logs/ssh_auth_analysis.txt"
```

### 5. Cron context alrededor del acceso inicial
```bash
# [risk:ro] [mode:auto]
# Ajustar las fechas según el timeline del incidente
journalctl --since "{{SINCE}}" 2>/dev/null | grep sshd \
  | tee "{{OUTPUT_DIR}}/logs/sshd_journal.txt"
```

<!-- MODULE:helpers.collect_ssh_artifacts -->
<!-- MODULE:helpers.collect_auth_logs -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- `last -F` da hora, IP y duración de sesiones. Crucial para correlacionar con auth.log.
- auth.log diferencia 3 métodos de autenticación:
  - `Accepted publickey` → llave SSH.
  - `Accepted password` → contraseña (requiere `PasswordAuthentication yes`).
  - `Accepted keyboard-interactive/pam` → vía PAM (puede ser password, OTP, etc.). Si `PasswordAuthentication=no` pero `KbdInteractiveAuthentication=yes` + `UsePAM=yes`, las passwords entran por aquí.
- `PermitRootLogin prohibit-password` → root solo por llave. Un `Accepted password for root` después de este setting es imposible sin override manual.
- Llaves en `authorized_keys` que NO están en backups → inserciones posteriores potencialmente del atacante.
- Comentario de llave (`4h1g4L0w4@proton.me`): verificar si correlaciona con identidad legítima de admin.
- SSH certificates (firmados por CA) tienen ID con `@dominio` — útil en enterprises con CA SSH.
- `lastb` con miles de intentos fallidos desde bots → ruido normal. Pocos intentos desde un rango IP pequeño → posible credential stuffing dirigido.

## Falsos positivos
- Llaves personales de admin con comment leetspeak (`4h1g4L0w4@proton.me`): pueden ser admins reales.
- Sesiones root `keyboard-interactive/pam` desde IPs de la empresa: admins con password/OTP fijo.
- Failed login de bots en miles para root: ruido normal de internet.

## IOC específicos
- `Accepted publickey for root from <AWS US-west IP>` con fingerprint RSA no visto en backups → vector inicial.
- Usuario `rpcd` (no estándar) creado y luego logins `keyboard-interactive/pam` → backdoor user.
- Llaves con comment `@protonmail` sin identidad legítima correlacionable.
- SSH host keys removidas/regeneradas (`rc.local` ejecutando `dpkg-reconfigure openssh-server`).
- `PermitRootLogin yes` o `PasswordAuthentication yes` en sshd_config.

## Buenas prácticas
- Baseline de fingerprints esperados por usuario (whitelist), almacenado en gestor de configuración.
- `PasswordAuthentication no` + `KbdInteractiveAuthentication no` (o OTP vía PAM con OATH/TOTP/Duo).
- `PermitRootLogin prohibit-password` como mínimo; idealmente `PermitRootLogin no` + sudo.
- Instalar `google-authenticator` para 2FA SSH (`ChallengeResponseAuthentication yes`).
- `LogLevel VERBOSE` en sshd_config para capturar fingerprints (default en OpenSSH moderno).
- Rotar llaves cada 90 días para admins, auditable con `etckeeper`.
- fail2ban para limitar ruido de brute force.
- Automatizar `ssh-keygen -lf` de todas las authorized_keys en pipeline de alerta.

## Referencias
- `man 5 sshd_config`, `man 8 sshd`
- MITRE ATT&CK: T1078, T1110, T1098, T1136, T1021.004
- OpenSSH hardening guide: https://www.ssh-audit.com
- `last`, `lastb`, `aureport -au` (auditd)
- Debian/Ubuntu `pam-auth-update` framework
