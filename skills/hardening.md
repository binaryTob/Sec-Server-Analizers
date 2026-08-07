---
id: "hardening"
name: "Skill: Hardening Linux — CIS Benchmarks"
version: "2.0"
category: "hardening"
phase: "recover"
risk: "reconf"
execution_mode: "confirm"
depends_on: ["incident_response"]
provides: []
triggers:
  - "Al final de un Compromise Assessment (sección hardening post-remediación)"
  - "Baseline post-remediación para prevenir re-infección"
  - "Auditoría sistemática de conformidad CIS"
mitre_attack:
  - "N/A (endurecimiento, no técnica de ataque)"
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar reporte de hardening"
  CIS_LEVEL:
    type: "enum"
    default: "1"
    required: false
    enum: ["1", "2"]
    description: "Nivel CIS Benchmark a auditar (1=server, 2=workstation/high-security)"
  AUTO_FIX:
    type: "boolean"
    default: false
    required: false
    description: "Aplicar remediación automática con usg fix (requiere confirmación)"
  SSH_ALLOW_USERS:
    type: "string"
    required: false
    description: "Lista de usuarios permitidos para SSH (separados por espacio)"
output:
  format: "json"
  schema: "output_schema"
---

# Skill: Hardening (Endurecimiento) Linux — CIS Benchmarks

## Objetivo
Comparar la configuración de un host Linux contra los controles CIS Benchmarks (CIS Ubuntu 22.04 L2) para detectar: permisos incorrectos, usuarios innecesarios, configuraciones inseguras, secretos expuestos, servicios expuestos y credenciales en texto plano. Generar un reporte de cumplimiento y aplicar remediación cuando se solicite.

## Cuándo usarla
- Al final de un Compromise Assessment (hardening post-remediación).
- Baseline post-remediación para prevenir re-infección.
- Auditoría sistemática de conformidad CIS.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de reporte |
| `{{CIS_LEVEL}}` | enum | no | `1` | Nivel CIS (1 o 2) |
| `{{AUTO_FIX}}` | boolean | no | `false` | Aplicar usg fix automático |
| `{{SSH_ALLOW_USERS}}` | string | no | — | Whitelist de usuarios SSH |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"/{initial,services,ssh,accounts,filesystem,logging,secrets,firewall}
echo "CIS AUDIT START: $(date -Iseconds) on $(hostname)" | tee "{{OUTPUT_DIR}}/manifest.txt"
```

## Secciones de auditoría CIS (Ubuntu Linux 22.04 v2.0)

### 1. Initial Setup
```bash
# [risk:ro] [mode:auto]
{
  echo "=== OS RELEASE ==="
  cat /etc/os-release
  echo "=== KERNEL ==="
  uname -r
  echo "=== INSTALLED PACKAGES COUNT ==="
  apt list --installed 2>/dev/null | wc -l
  echo "=== FILE INTEGRITY TOOLS ==="
  dpkg -l 2>/dev/null | grep -E 'aide|tripwire|osquery|wazuh'
  echo "=== SECURE BOOT ==="
  mokutil --sb-state 2>/dev/null
  echo "=== KERNEL HARDENING PARAMS ==="
  sysctl -a 2>/dev/null | grep -E \
    "kernel.randomize_va_space|kernel.kptr_restrict|kernel.dmesg_restrict|kernel.perf_event_paranoid|fs.suid_dumpable|net.ipv4.conf.all.send_redirects|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.rp_filter|net.ipv4.tcp_syncookies"
} | tee "{{OUTPUT_DIR}}/initial/initial_setup.txt"
```

### 2. Servicios innecesarios (CIS 2.x)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== ENABLED SERVICES ==="
  systemctl list-unit-files --state=enabled
  echo "=== UNSAFE SERVICES CHECK ==="
  for svc in avahi-daemon cups nfs rpcbind ypserv dnsmasq snmpd slapd nginx vsftpd ftp lirc rsh-server telnet; do
    state=$(systemctl is-enabled "$svc" 2>/dev/null)
    echo "$svc: ${state:-not-found}"
  done
} | tee "{{OUTPUT_DIR}}/services/services_audit.txt"
```

### 3. SSH (CIS 5.x)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SSHD SECURITY PARAMS ==="
  grep -E "^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol|MaxAuthTries|ClientAliveInterval|ClientAliveCountMax|X11Forwarding|AllowTcpForwarding|AllowUsers|AllowGroups|IgnoreRhosts|HostbasedAuthentication|PermitTunnel|KbdInteractiveAuthentication)" \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
  echo "=== SSHD -T (effective config) ==="
  sshd -T 2>/dev/null | grep -E \
    "permitrootlogin|passwordauthentication|kbdinteractiveauthentication|maxauthtries|clientaliveinterval|clientalivecountmax|ignorerhosts|hostbasedauthentication|permitemptypasswords|x11forwarding|allowtcpforwarding|permittunnel"
} | tee "{{OUTPUT_DIR}}/ssh/ssh_audit.txt"
```

Recomendaciones CIS:
- `PermitRootLogin no` (preferible a `prohibit-password`)
- `PasswordAuthentication no`
- `KbdInteractiveAuthentication no` (o 2FA)
- `MaxAuthTries 3`, `ClientAliveInterval 300`, `ClientAliveCountMax 0`
- `IgnoreRhosts yes`, `HostbasedAuthentication no`
- `PermitEmptyPasswords no`
- Remover `X11Forwarding` a menos que sea necesario

### 4. Cuentas / Políticas de Password (CIS 6.x)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== PASSWORD POLICIES ==="
  grep -E "PASS_" /etc/login.defs 2>/dev/null
  echo "=== ROOT PASSWORD AGING ==="
  chage -l root 2>/dev/null
  echo "=== USER PASSWORD AGING ==="
  for u in $(awk -F: '$3>=1000 {print $1}' /etc/passwd); do
    chage -l "$u" 2>/dev/null
  done
  echo "=== PAM QUALITY ==="
  grep -rE "pam_pwquality|pam_tally2|pam_faillock|pam_faildelay" /etc/pam.d/ 2>/dev/null
  echo "=== UID 0 USERS (should be only root) ==="
  awk -F: '$3==0 {print $1}' /etc/passwd
  echo "=== EMPTY PASSWORDS ==="
  awk -F: '$2=="" || $2=="!" {print $1,$2}' /etc/shadow 2>/dev/null
  echo "=== INACTIVE ACCOUNT POLICY ==="
  useradd -D 2>/dev/null | grep INACTIVE
  echo "=== NON-STANDARD USERS ==="
  awk -F: '$3>=1000 && $3<65534 {print $1,$3,$6,$7}' /etc/passwd
} | tee "{{OUTPUT_DIR}}/accounts/accounts_audit.txt"
```

### 5. Sudo / Privilege Escalation (CIS 5.x sudo)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SUDOERS ==="
  cat /etc/sudoers 2>/dev/null
  echo "=== SUDOERS.D ==="
  ls -la /etc/sudoers.d/ 2>/dev/null
  for f in /etc/sudoers.d/*; do echo "### $f"; cat "$f" 2>/dev/null; done
  echo "=== NOPASSWD / ALL ENTRIES ==="
  grep -rE "NOPASSWD|ALL=\(ALL" /etc/sudoers /etc/sudoers.d/* 2>/dev/null
  echo "=== SUDO GROUP MEMBERS ==="
  for g in sudo admin wheel; do getent group "$g" 2>/dev/null; done
} | tee "{{OUTPUT_DIR}}/accounts/sudo_audit.txt"
```

### 6. Permisos del filesystem (CIS 1.x)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== CRITICAL FILE PERMISSIONS ==="
  stat -c '%n %a %U:%G' /etc/passwd /etc/shadow /etc/group /etc/gshadow /boot/grub/grub.cfg 2>/dev/null
  echo "=== SUID FILES ==="
  find / -xdev -type f -perm -4000 2>/dev/null
  echo "=== SGID FILES ==="
  find / -xdev -type f -perm -2000 2>/dev/null
  echo "=== FILE CAPABILITIES ==="
  getcap -r / 2>/dev/null
  echo "=== WORLD-WRITABLE DIRS (no sticky) ==="
  find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
  echo "=== /tmp MOUNT OPTIONS ==="
  mount | grep -E "\b/tmp\b|\b/var/tmp\b"
} | tee "{{OUTPUT_DIR}}/filesystem/filesystem_audit.txt"
```

### 7. Cron Restringido
```bash
# [risk:ro] [mode:auto]
{
  echo "=== CRON DIRECTORIES ==="
  ls -la /etc/cron* /var/spool/cron 2>/dev/null
  echo "=== CRON ALLOW/DENY ==="
  cat /etc/cron.allow /etc/cron.deny 2>/dev/null
  echo "=== AT ALLOW/DENY ==="
  cat /etc/at.allow /etc/at.deny 2>/dev/null
} | tee "{{OUTPUT_DIR}}/filesystem/cron_restrictions.txt"
```

### 8. Logging/Audit (CIS 4.x)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== LOGGING PACKAGES ==="
  dpkg -l 2>/dev/null | grep -E 'rsyslog|auditd|syslog-ng'
  echo "=== RSYSLOG/AUDITD STATUS ==="
  systemctl is-active rsyslog auditd 2>/dev/null
  echo "=== AUDITD CONFIG ==="
  cat /etc/audit/auditd.conf 2>/dev/null
  echo "=== AUDIT RULES ==="
  ls -la /etc/audit/rules.d/ 2>/dev/null
  augenrules --check 2>/dev/null
  echo "=== REMOTE SYSLOG ==="
  grep -rE "@@|@.*514" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
} | tee "{{OUTPUT_DIR}}/logging/logging_audit.txt"
```

### 9. Kernel modules / USB restrictions
```bash
# [risk:ro] [mode:auto]
{
  echo "=== MODPROBE BLACKLIST ==="
  cat /etc/modprobe.d/*.conf 2>/dev/null
  echo "=== FILESYSTEM MODULES (should be disabled) ==="
  for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
    echo "$fs: $(grep -r "$fs" /etc/modprobe.d/ 2>/dev/null | head -1)"
  done
  echo "=== USB STORAGE ==="
  grep -r "usb-storage" /etc/modprobe.d/ 2>/dev/null
} | tee "{{OUTPUT_DIR}}/filesystem/kernel_modules.txt"
```

### 10. Secretos/credenciales expuestos
```bash
# [risk:ro] [mode:auto]
{
  echo "=== PLAINTEXT SECRETS IN /etc,/opt,/root,/home ==="
  grep -rE "^(password|passwd|api_key|secret|token|private_key|client_secret)" \
    /etc /opt /root /home /var/www 2>/dev/null | head -50
  echo "=== PRIVATE KEYS EXPOSED ==="
  grep -rEi "BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY|---BEGIN PRIVATE KEY" \
    /etc /opt /root /home 2>/dev/null | head -20
  echo "=== SENSITIVE DOTFILES ==="
  find / -xdev \( -name ".env" -o -name ".npmrc" -o -name ".pgpass" -o -name "credentials" -o -name ".netrc" \) 2>/dev/null
  echo "=== TOKENS IN CRONTABS ==="
  grep -hE "Bearer|Authorization: Bearer|api_key|access_token" \
    /var/spool/cron/crontabs/* /etc/cron.d/* 2>/dev/null
  echo "=== SSH PRIVATE KEYS ==="
  file /root/.ssh/id_* 2>/dev/null
} | tee "{{OUTPUT_DIR}}/secrets/secrets_scan.txt"
```

### 11. Exposición de servicios (escucha en 0.0.0.0)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SERVICES LISTENING ON 0.0.0.0 ==="
  ss -tulnp | awk '$5 ~ /0\.0\.0\.0:|\[::\]:|:\*/ {print}'
  echo "=== DANGEROUS EXPOSED SERVICES ==="
  for port in 6379 11211 27017 9200 8084 3001 9090; do
    ss -tulnp | grep ":$port " && echo "WARNING: port $port exposed"
  done
} | tee "{{OUTPUT_DIR}}/firewall/exposed_services.txt"
```

### 12. Firewall
```bash
# [risk:ro] [mode:auto]
{
  echo "=== UFW STATUS ==="
  ufw status verbose 2>/dev/null
  echo "=== IPTABLES ==="
  iptables -L -n -v 2>/dev/null | head -30
  echo "=== NFTABLES ==="
  nft list ruleset 2>/dev/null | head -50
} | tee "{{OUTPUT_DIR}}/firewall/firewall_audit.txt"
```

### 13. Time sync & NTP
```bash
# [risk:ro] [mode:auto]
{
  echo "=== TIMEDATECTL ==="
  timedatectl 2>/dev/null
  echo "=== TIME SERVICES ==="
  for svc in systemd-timesyncd chronyd ntpd; do
    systemctl is-active "$svc" 2>/dev/null && echo "$svc: active"
  done
} | tee "{{OUTPUT_DIR}}/initial/time_sync.txt"
```

### 14. APT GPG keys / repos
```bash
# [risk:ro] [mode:auto]
{
  echo "=== APT TRUSTED KEYS ==="
  ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null
  echo "=== APT SOURCES ==="
  cat /etc/apt/sources.list 2>/dev/null
  ls -la /etc/apt/sources.list.d/ 2>/dev/null
  echo "=== 3RD PARTY REPOS ==="
  apt-key list 2>/dev/null | head -50
} | tee "{{OUTPUT_DIR}}/initial/apt_security.txt"
```

### 15. Auto-fix con USG (si se solicita) — [risk:reconf] [mode:confirm]
```bash
# [risk:reconf] [mode:confirm] [requires:usg]
if [ "{{AUTO_FIX}}" = "true" ]; then
  apt install -y usg 2>/dev/null
  usg fix --level={{CIS_LEVEL}} 2>&1 | tee "{{OUTPUT_DIR}}/usg_fix.log"
  echo "[HARDENING] CIS Level {{CIS_LEVEL}} auto-fix aplicado con usg"
fi
```

<!-- MODULE:helpers.hash_evidence -->

## Interpretación / Riesgos mapeados
- `PermitRootLogin prohibit-password` → root puede loguearse con llave. Mejor `no` (usar sudo).
- `PasswordAuthentication yes` → vector de brute force primitivo.
- `KbdInteractiveAuthentication yes` → si PAM permite passwords, backdoor users pueden bypassear `PasswordAuthentication=no`. Configurar `pam_unix` deny si se quiere pure keyless.
- `NOPASSWD:ALL` en grupo sudo → cualquier cuenta sudo comprometida = root instantáneo.
- Usuarios UID==0 fuera de root → falla CIS directa.
- Tokens `Authorization: Bearer` en crontabs → secret exposure en texto plano.
- Servicios en `0.0.0.0:6379` (Redis) sin auth → desastre de exposición.
- Auditd deshabilitado → sin trail post-incidente.

## IOC específicos de hardening pentest
- `/etc/ld.so.preload` con contenido (debe estar vacío o no existir → rootkit).
- `PermitRootLogin yes`, `PasswordAuthentication yes` en sshd_config → backdoor habilitador.
- Tokens `Authorization: Bearer 045e...` en crontabs (logged plaintext).
- `chmod 644 /etc/shadow` — shadow world-readable.
- `/tmp` mounted `rw` sin `noexec,nodev,nosuid`.

## Buenas prácticas
- Aplicar CIS Level 1 baseline + Level 2 en servidores de producción.
- Harden con `usg` (Ubuntu Security Guide): `apt install usg && usg fix --level=1`.
- SSH hardening completo: `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no` (excepto OTP).
- Usar SSH certificates (step-ca, Teleport) → elimina la gestión de authorized_keys.
- Rotar SSH keys / service tokens / API keys cada 90 días; usar Vault / SOPS para secretos.
- `pam_faillock` para bloquear cuentas tras N intentos fallidos.
- Agregar reglas auditd para: `ld.so.preload`, `/etc/passwd`, `/etc/sudoers`.
- Set `net.ipv4.conf.all.rp_filter=1`, `tcp_syncookies=1`, `accept_redirects=0`.
- Egress firewall para bloquear pools de minado / dominios known-bad.
- Deshabilitar servicios no usados: `systemctl disable rpcbind`.
- Si hubo compromiso confirmado: generar nuevas SSH host keys (`dpkg-reconfigure openssh-server`).
- Eliminar paquetes inseguros: `apt purge telnet rsh-client`.

## Referencias
- CIS Benchmarks Ubuntu Linux 22.04 v2.0.0 — Centre for Internet Security
- Ubuntu Security Guide (usg): `usg fix`
- Lynis: `apt install lynis && lynis audit system` — auditoría CIS-like open source
- NIST SP 800-53: controles AC, IA, SC
- Mozilla SSH Guidelines: https://infosec.mozilla.org/guidelines/openssh
- `man 5 login.defs`, `man 8 auditctl`, `man 5 modprobe.d`, `man sshd_config`
