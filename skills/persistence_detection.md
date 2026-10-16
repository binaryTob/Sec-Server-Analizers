---
id: "persistence_detection"
name: "Skill: Persistence Detection en Linux"
version: "2.0"
category: "detection"
phase: "ident"
risk: "readonly"
execution_mode: "auto"
depends_on: ["linux_forensics"]
provides: ["incident_response", "IOC_hunting"]
triggers:
  - "Compromise Assessment (presencia de persistencia confirma que el atacante sobrevive a reboot)"
  - "Tras detectar malware o backdoor user"
  - "Auditoría de rutina de vectores de autostart"
mitre_attack:
  - "T1543.002"  # systemd service
  - "T1053.003"  # cron
  - "T1053.006"  # systemd timers
  - "T1037.004"  # rc.local / init.d
  - "T1547.004"  # shell rc / profiles
  - "T1098"      # Account Manipulation (SSH keys)
  - "T1078"      # Valid Accounts
  - "T1136.001"  # Create Account
  - "T1547.007"  # ld.so.preload
  - "T1548.003"  # sudo
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar evidencia"
  BACKUP_BASELINE_DIR:
    type: "filepath"
    required: false
    description: "Directorio con baseline anterior para diff (ej: backup de etckeeper)"
  SUSPECT_USERS:
    type: "string"
    default: "synthetic-user"
    required: false
    description: "Lista de nombres de usuario sospechosos a verificar"
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "filepath"
    value: "/example/cron-entry"
    context: "Ruta sintética de ejemplo; verificar el host antes de usarla"
    source: "synthetic-example"
    confidence: "high"
  - type: "filepath"
    value: "/example/loader.conf -> /example/synthetic-library.so"
    context: "Rutas sintéticas de ejemplo; verificar el host antes de usarlas"
    source: "synthetic-example"
    confidence: "high"
  - type: "user"
    value: "synthetic-user"
    context: "Marcador sintético; no representa una cuenta real"
    source: "synthetic-example"
    confidence: "high"
---

# Skill: Persistence Detection en Linux

## Objetivo
Enumerar exhaustivamente todos los mecanismos de persistencia usados por atacantes en un host Linux: cron, systemd, init, rc.local, shell rc, SSH authorized_keys, PAM, LD_PRELOAD, sudoers, kernel modules y backdoor users.

## Cuándo usarla
- Siempre en un Compromise Assessment (presencia de persistencia confirma que el atacante sobrevive a reboot).
- Tras detectar malware o backdoor user, para enumerar todos los puntos de anclaje.
- Auditoría programada de vectores T1547/T1053/T1136.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de salida |
| `{{BACKUP_BASELINE_DIR}}` | filepath | no | — | Baseline previo para comparación |
| `{{SUSPECT_USERS}}` | string | no | `synthetic-user` | Marcador de ejemplo; reemplazar sólo con identidades verificadas |

## Pre-flight
```bash
# [risk:info] [mode:auto]
umask 077
mkdir -p "{{OUTPUT_DIR}}"/{cron,systemd,ssh,sudo,users,shell_rc}
```

## Comandos: enumerar cada vector T1547/T1053/T1136

### 1. systemd (T1543.002, T1053.006 timers)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== ENABLED UNITS ==="
  systemctl list-unit-files --state=enabled
  echo "=== RUNNING SERVICES ==="
  systemctl list-units --type=service --state=running
  echo "=== FAILED SERVICES ==="
  systemctl list-units --type=service --state=failed
  echo "=== TIMERS ==="
  systemctl list-timers --all
  echo "=== UNIT FILES TREE ==="
  ls -laR /etc/systemd/system/
  echo "=== RECENTLY MODIFIED UNITS ==="
  find /etc/systemd /lib/systemd/system -mtime -90 -type f 2>/dev/null
  echo "=== DROP-IN OVERRIDES ==="
  find /etc/systemd/system/ -name "*.d" -type d 2>/dev/null
  find /etc/systemd/system/ -name "override.conf" 2>/dev/null
  echo "=== GENERATORS ==="
  ls /etc/systemd/system-generators/ /usr/lib/systemd/system-generators/ 2>/dev/null
} | tee "{{OUTPUT_DIR}}/systemd/systemd_enum.txt"
```

### 2. cron (T1053.003)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== /etc/crontab ==="
  cat /etc/crontab
  echo "=== /etc/cron.d/* ==="
  for f in /etc/cron.d/*; do echo "### $f"; cat "$f"; done
  echo "=== CRON DIRS ==="
  ls -la /etc/cron.{hourly,daily,weekly,monthly} 2>/dev/null
  echo "=== USER CRONTABS ==="
  crontab -l 2>/dev/null
  for u in $(awk -F: '$7 ~ /sh$/ {print $1}' /etc/passwd); do
    echo "### crontab -u $u"
    crontab -u "$u" -l 2>/dev/null
  done
  echo "=== SPOOL DIRS ==="
  ls -laR /var/spool/cron/ 2>/dev/null
  ls -laR /var/spool/anacron/ 2>/dev/null
  echo "=== AT JOBS ==="
  atq 2>/dev/null
  echo "=== HIGH-FREQUENCY CRON ENTRIES ==="
  grep -rE "(\*/[0-9]+\s\*\s\*\s\*\s\*\s+root\s+/[a-z])" /etc/cron* 2>/dev/null
} | tee "{{OUTPUT_DIR}}/cron/cron_enum.txt"
```

### 3. rc.local / init.d / rc*.d (T1037.004, T1547.006)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== rc.local ==="
  cat /etc/rc.local 2>/dev/null
  echo "=== rc*.d / init.d ==="
  ls -la /etc/rc*.d/ /etc/init.d/ 2>/dev/null
  echo "=== MODULE AUTOLOAD ==="
  ls -la /etc/modules-load.d/ 2>/dev/null
  cat /etc/modules-load.d/* 2>/dev/null
  ls -la /etc/modprobe.d/ 2>/dev/null
  cat /etc/modprobe.d/*.conf 2>/dev/null
} | tee "{{OUTPUT_DIR}}/init_rc.txt"
```

### 4. shell rc / profiles (T1547.004)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== /etc/profile ==="
  cat /etc/profile 2>/dev/null
  echo "=== /etc/bash.bashrc ==="
  cat /etc/bash.bashrc 2>/dev/null
  echo "=== /etc/profile.d/ ==="
  ls -la /etc/profile.d/ 2>/dev/null
  for f in /etc/profile.d/*.sh; do echo "### $f"; cat "$f"; done
  echo "=== ROOT SHELL RC ==="
  for f in .bashrc .bash_profile .profile .bash_login .bash_aliases; do
    echo "### /root/$f"
    cat "/root/$f" 2>/dev/null
  done
  echo "=== /etc/environment ==="
  cat /etc/environment 2>/dev/null
  echo "=== USER SHELL RC ==="
  while IFS=: read -r u _ uid _ _ H shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] && (( uid >= 1000 && uid < 65534 )) || continue
    [[ "$shell" =~ /(bash|sh)$ && "$H" == /* && -d "$H" ]] || continue
    for f in .bashrc .profile .bash_aliases; do
      if [ -f "$H/$f" ]; then
        echo "### $u -> $H/$f"
        cat "$H/$f" 2>/dev/null
      fi
    done
  done < /etc/passwd
} | tee "{{OUTPUT_DIR}}/shell_rc/shell_enum.txt"
```

### 5. SSH (T1098, T1078, T1136)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== AUTHORIZED_KEYS ==="
  while IFS=: read -r u _ _ _ _ H shell; do
    [[ "$shell" =~ /(bash|sh)$ && "$H" == /* && -d "$H" ]] || continue
    if [ -f "$H/.ssh/authorized_keys" ]; then
      echo "### $u -> $H/.ssh/authorized_keys"
      cat "$H/.ssh/authorized_keys"
      ssh-keygen -lf "$H/.ssh/authorized_keys" 2>/dev/null
    fi
  done < /etc/passwd
  echo "=== AUTHORIZED_KEYS BACKUPS ==="
  find /root/.ssh /home -name "authorized_keys*" -ls 2>/dev/null
  echo "=== SSHD CONFIG ==="
  grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractive|AllowUsers|AllowGroups|Match|AuthorizedKeysFile|PermitEmptyPasswords|X11Forwarding|AllowTcpForwarding|PermitTunnel)" \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
  echo "=== HOST KEYS ==="
  ls -la /etc/ssh/ssh_host_* 2>/dev/null
  echo "=== SSH CERTIFICATES ==="
  ls -la /etc/ssh/ssh_ca.pub /etc/ssh/auth_principals 2>/dev/null
} | tee "{{OUTPUT_DIR}}/ssh/ssh_enum.txt"
```

### 6. sudoers / PAM (T1548.003)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== /etc/sudoers ==="
  cat /etc/sudoers 2>/dev/null
  echo "=== /etc/sudoers.d/ ==="
  for f in /etc/sudoers.d/*; do echo "### $f"; cat "$f"; done
  echo "=== NOPASSWD ENTRIES ==="
  grep -rE "NOPASSWD|ALL=\(ALL" /etc/sudoers /etc/sudoers.d/* 2>/dev/null
  echo "=== SUDO GROUP MEMBERS ==="
  for g in sudo admin wheel; do getent group "$g" 2>/dev/null; done
  echo "=== PAM CONFIG ==="
  ls -la /etc/pam.d/ 2>/dev/null
  for f in sshd su common-auth; do
    echo "### /etc/pam.d/$f"
    cat "/etc/pam.d/$f" 2>/dev/null
  done
} | tee "{{OUTPUT_DIR}}/sudo/sudo_pam.txt"
```

### 7. Backdoor users (T1136.001)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== NON-SYSTEM USERS (UID>=1000) ==="
  awk -F: '$3>=1000 && $3<65534 {print}' /etc/passwd
  echo "=== USERS WITH PASSWORD SET ==="
  awk -F: '($2=="") {state="EMPTY"} ($2 ~ /^[!*]/) {state="LOCKED"} ($2!="" && $2 !~ /^[!*]/) {state="HASH_SET"} {print $1,state,$3}' /etc/shadow
  echo "=== UID 0 USERS (should only be root) ==="
  awk -F: '$3==0 {print $1}' /etc/passwd
  echo "=== EMPTY PASSWORDS ==="
  awk -F: '$2=="" {print $1,"EMPTY"}' /etc/shadow
  echo "=== SUSPECT SERVICE USERS ==="
  IFS=','; for u in {{SUSPECT_USERS}}; do
    id "$u" 2>/dev/null && grep "^$u:" /etc/passwd
  done
  echo "=== USER CREATION IN LOGS ==="
  grep -hE "useradd|usermod" /var/log/auth.log* 2>/dev/null
} | tee "{{OUTPUT_DIR}}/users/users_backdoor.txt"
```

### 8. LD_PRELOAD / libraries (T1547.007, T1574.006)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== /etc/ld.so.preload ==="
  cat /etc/ld.so.preload 2>/dev/null
  ls -la /etc/ld.so.preload 2>/dev/null
  echo "=== /etc/ld.so.conf ==="
  cat /etc/ld.so.conf 2>/dev/null
  ls /etc/ld.so.conf.d/ 2>/dev/null
  cat /etc/ld.so.conf.d/*.conf 2>/dev/null
  echo "=== CUSTOM LIBS IN /usr/local/lib ==="
  ls -la /usr/local/lib/*.so /usr/local/lib/*.so.* 2>/dev/null
  echo "=== LD_PRELOAD IN ENV FILES ==="
  grep -rE "LD_PRELOAD" /etc /root /home 2>/dev/null
  echo "=== ACTIVE LD_PRELOAD IN /proc ==="
  for p in /proc/[0-9]*/environ; do
    grep -l LD_PRELOAD "$p" 2>/dev/null
  done
} | tee "{{OUTPUT_DIR}}/ld_preload.txt"
```

<!-- MODULE:helpers.collect_persistence_vectors -->
<!-- MODULE:helpers.collect_ssh_artifacts -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- Una tarea frecuente que lanza un binario no verificado → indicador que requiere correlación con baseline y propietario.
- Usuario nuevo (UID 1000-65000) con shell → investigar historial y fecha de creación.
- Hash de password MD5 (`$1$`) en usuario de servicio → el atacante seteó una contraseña débil.
- `NOPASSWD:` en sudoers → generalmente inseguro; verificar si fue añadido por el atacante.
- Shell RC que carga un archivo fuera del baseline → investigar origen, propietario y persistencia.
- `authorized_keys` con una clave no correlacionable contra el inventario autorizado → posible persistencia.
- `/etc/ld.so.preload` con tamaño > 0 bytes → sospecha alta de rootkit userland.
- Backups de `authorized_keys.*` → comparar períodos de inserción de llaves.
- Drop-in overrides en `/etc/systemd/system/*.d/` agregando `ExecStartPre=` o `ExecStartPost=` → IOC.

## Falsos positivos
- Llaves ed25519 de empleados agregadas/removidas → diff cronológico para distinguir de atacante.
- `NOPASSWD` para deployments de Ansible/Jenkins → legítimo en infra-as-code.
- Backups automáticos de `authorized_keys` (etckeeper) → esperado en entornos administrados.

## IOC específicos comunes
- Una entrada cron no esperada con nombre que imita una tarea de sistema.
- `/etc/ld.so.preload` apuntando a una biblioteca fuera del baseline autorizado.
- Una cuenta inesperada con UID, shell, grupos o fecha de creación anómalos.
- Claves en `authorized_keys` no correlacionables contra un inventario autorizado.
- Drop-in overrides en `/etc/systemd/system/docker.service.d/` con `ExecStartPost=...`.

## Buenas prácticas
- Instalar `etckeeper` para hacer diff automático de `/etc` con git.
- Endurecer PAM con `libpam-pwquality`, denegar passwords débiles.
- `PermitRootLogin prohibit-password` (mínimo), `PasswordAuthentication no`.
- Checklist de autostart automatizado: auditar periódicamente los vectores T1547.
- Revisar `/etc/updatedb.conf` y `/etc/modprobe.d/*` — escondites comunes.

## Referencias
- MITRE ATT&CK: T1547, T1543.002, T1053.003, T1037.004, T1547.004, T1547.007, T1548.003, T1136, T1098, T1078
- Trail of Bits: "Linux Persistence Techniques" — https://github.com/trailofbits/
- `chkrootkit`, `rkhunter`, `lynis` — herramientas de auditoría sistemática
- `etckeeper` — control de versiones para `/etc`
