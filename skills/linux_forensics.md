---
id: "linux_forensics"
name: "Skill: Linux Forensics"
version: "2.0"
category: "forensics"
phase: "collect"
risk: "readonly"
execution_mode: "auto"
depends_on: []
provides: ["incident_response", "cryptominer_detection", "malware_hunting"]
triggers:
  - "Sospecha o confirmación de compromiso en host Linux"
  - "Compromise Assessment completo"
  - "Antes de cualquier acción de remediación (preservar evidencia)"
mitre_attack:
  - "N/A (colección forense, no técnica de ataque)"
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio raíz para toda la evidencia recolectada"
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
    description: "Ventana temporal de inicio para logs (journalctl --since)"
  UNTIL:
    type: "datetime"
    default: "now"
    required: false
    description: "Ventana temporal de fin para logs"
  SUSPECT_PID:
    type: "integer"
    required: false
    description: "PID de un proceso sospechoso para análisis forense detallado"
output:
  format: "json"
  schema: "output_schema"
---

# Skill: Linux Forensics

## Objetivo
Recolectar, preservar y analizar evidencia de un sistema Linux comprometido **sin alterar el estado del sistema** (modo solo-lectura estricto), siguiendo la metodología profesional DFIR con orden de volatilidad RFC 3227.

## Cuándo usarla
- Cuando se sospecha o confirma un compromiso en un host Linux.
- Compromise Assessment completo.
- Antes de remediar para no contaminar la evidencia.

## Principio fundamental: Orden de Volatilidad (RFC 3227 BCP 36)
Recolectar primero lo más volátil: memoria → conexiones de red → procesos → sysctl/rutas → /proc → logs → filesystem.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio raíz de evidencia |
| `{{SINCE}}` | datetime | no | `1 day ago` | Inicio de ventana temporal |
| `{{UNTIL}}` | datetime | no | `now` | Fin de ventana temporal |
| `{{SUSPECT_PID}}` | integer | no | — | PID sospechoso a analizar |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"/{proc,net,logs,files,persistence}
echo "FORENSIC COLLECTION START: $(date -Iseconds) on $(hostname)" \
  | tee "{{OUTPUT_DIR}}/manifest.txt"
```

## Comandos por etapa

### 1. Contexto del sistema (primera captura)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== OS RELEASE ==="
  cat /etc/os-release
  echo "=== UNAME ==="
  uname -a
  echo "=== UPTIME ==="
  uptime
  echo "=== DATE ==="
  date -Iseconds
  echo "=== LAST REBOOT ==="
  last reboot | head -5
  echo "=== ARCH ==="
  arch
  echo "=== CPU ==="
  lscpu | head -10
  echo "=== MEMORY ==="
  free -h
} | tee "{{OUTPUT_DIR}}/system_context.txt"
```

### 2. Procesos y memoria
```bash
# [risk:ro] [mode:auto]
{
  echo "=== ALL PROCESSES (CPU sort) ==="
  ps -eo pid,ppid,user,lstart,etime,pcpu,pmem,comm,args --sort=-pcpu | head -40
  echo "=== ALL PROCESSES (RSS sort) ==="
  ps -eo pid,ppid,user,pmem,rss,vsz,args --sort=-rss | head -30
  echo "=== PS vs /proc COUNT ==="
  echo "ps=$(ps -e --no-headers | wc -l)  proc=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
  echo "=== PROCESSES FROM /tmp, /dev/shm, /var/tmp ==="
  ps -eo pid,user,args | grep -E "/tmp|/dev/shm|/var/tmp" | grep -v grep
} | tee "{{OUTPUT_DIR}}/proc/processes.txt"

# Procesos con binario borrado pero cargado (deleted-but-open)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" \
  | tee "{{OUTPUT_DIR}}/proc/deleted_exe.txt"
```

<!-- MODULE:helpers.collect_process_detail -->
<!-- MODULE:helpers.collect_volatile -->

### 3. Red (estado completo)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== LISTENERS ==="
  ss -tulnp
  echo "=== ESTABLISHED ==="
  ss -tnp state established
  echo "=== DESTINATIONS ==="
  ss -tan state established | awk '{print $5}' | sort -u
  echo "=== INTERFACES ==="
  ip -br a
  ip -br link
  echo "=== ROUTES ==="
  ip route show
  echo "=== HOSTS ==="
  cat /etc/hosts
  echo "=== RESOLV ==="
  cat /etc/resolv.conf
  echo "=== IPTABLES ==="
  iptables -L -n -v 2>/dev/null
  iptables -t nat -L -n -v 2>/dev/null
  echo "=== NFTABLES ==="
  nft list ruleset 2>/dev/null
} | tee "{{OUTPUT_DIR}}/net/network_state.txt"
```

<!-- MODULE:helpers.collect_network_state -->

### 4. Persistencia (exhaustiva)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== CRONTAB ==="; cat /etc/crontab
  echo "=== CRON.D ==="; for f in /etc/cron.d/*; do echo "### $f"; cat "$f"; done
  echo "=== USER CRONTABS ==="
  crontab -l 2>/dev/null
  for u in $(awk -F: '$7 ~ /sh$/ {print $1}' /etc/passwd); do
    crontab -u "$u" -l 2>/dev/null
  done
  ls -laR /var/spool/cron/ > "{{OUTPUT_DIR}}/persistence/cron_spool.txt"
  echo "=== SYSTEMD ENABLED ==="; systemctl list-unit-files --state=enabled
  echo "=== SYSTEMD RUNNING ==="; systemctl list-units --type=service --state=running
  echo "=== SYSTEMD TIMERS ==="; systemctl list-timers --all
  ls -laR /etc/systemd/system/ > "{{OUTPUT_DIR}}/persistence/systemd_units.txt"
  echo "=== SHELL RC ==="
  cat /root/.bashrc /root/.profile /etc/profile 2>/dev/null
  ls -la /etc/profile.d/ > "{{OUTPUT_DIR}}/persistence/profile_d.txt"
  echo "=== RC.LOCAL ==="; cat /etc/rc.local 2>/dev/null
  ls -la /etc/rc*.d /etc/init.d/ > "{{OUTPUT_DIR}}/persistence/rc_dirs.txt"
  echo "=== LD.SO.PRELOAD ==="; cat /etc/ld.so.preload 2>/dev/null
  ls -la /etc/ld.so.preload > "{{OUTPUT_DIR}}/persistence/ld_preload_stat.txt"
} | tee "{{OUTPUT_DIR}}/persistence/persistence_enum.txt"
```

<!-- MODULE:helpers.collect_persistence_vectors -->
<!-- MODULE:helpers.collect_ssh_artifacts -->

### 5. Caza de IOC en filesystem
```bash
# [risk:ro] [mode:auto]
{
  echo "=== SUID FILES ==="
  find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -4000 2>/dev/null
  echo "=== SGID FILES ==="
  find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -2000 2>/dev/null
  echo "=== EXECUTABLES IN TEMP DIRS ==="
  find /tmp /var/tmp /dev/shm -type f -exec file {} \; 2>/dev/null | grep -iE 'elf|executable|script'
  echo "=== FILES MODIFIED LAST 7d IN /etc ==="
  find /etc -mtime -7 -type f 2>/dev/null
  echo "=== MALWARE SIGNATURE GREP ==="
  grep -rEi "xmrig|kinsing|kdevtmpfsi|cnrig|minerd|cryptonight|stratum|monero|localhost0\.xyz|teamtnt|perfctl|redtail|rocke|sysrv" \
    /etc/ /root/ /var/spool/cron/ 2>/dev/null
} | tee "{{OUTPUT_DIR}}/files/ioc_scan.txt"
```

### 6. Logs
```bash
# [risk:ro] [mode:auto]
{
  echo "=== AUTH LOGS ==="
  grep -hE "Accepted|Failed|Invalid|useradd|usermod|sudo:|su:" /var/log/auth.log /var/log/auth.log.1 2>/dev/null
  echo "=== LAST ==="
  last -F | head -40
  echo "=== LASTB ==="
  lastb -F | head -20
  echo "=== ERRORS ==="
  grep -iE "error|panic|segfault|out of memory" /var/log/syslog /var/log/kern.log 2>/dev/null | tail -30
  echo "=== JOURNAL ==="
  journalctl --since "{{SINCE}}" --until "{{UNTIL}}" 2>/dev/null
} | tee "{{OUTPUT_DIR}}/logs/auth_and_system.txt"
```

<!-- MODULE:helpers.collect_auth_logs -->

### 7. Verificación de integridad de paquetes
```bash
# [risk:ro] [mode:auto]
{
  echo "=== DPKG VERIFY ==="
  dpkg --verify 2>/dev/null
  echo "=== DEBSUMS ==="
  debsums -c 2>/dev/null
  echo "=== RPM VERIFY ==="
  rpm -Va 2>/dev/null
} | tee "{{OUTPUT_DIR}}/files/integrity_check.txt"
```

<!-- MODULE:helpers.verify_binaries -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- Procesos con `(deleted)` en `/proc/*/exe` → binario borrado pero cargado (típico de malware en ejecución).
- `ps != /proc` → posible rootkit LKM o namespace confusion (re-validar).
- Archivos SUID/SGID fuera de los del OS base → investigar. Los legítimos son: `newgrp, passwd, sudo, su, mount, umount, pkexec, gpasswd, chsh, chfn, fusermount, ssh-agent, chage, crontab, expiry, dotlockfile, unix_chkpwd, postdrop, postqueue`.
- Cualquier línea añadida en `cron`, `systemd`, `.bashrc` o `/etc/ld.so.preload` → IOC de persistencia.
- `dpkg --verify` marcado `??5` → archivo modificado vs paquete (puede ser benigno en conffiles como `/etc/default/*`).

## Falsos positivos comunes
- chkrootkit "14 process hidden for ps": race condition con procesos efímeros (sshd, cron, ps mismo). Re-validar.
- ifpromisc en `systemd-networkd`: daemon legítimo de red, FP.
- `dpkg --verify` en conffiles modificados por admin (jenkins.service, motd-news): FP frecuente.
- `getcap` en `/usr/bin/ping` y `/usr/bin/mtr-packet`: capabilities estándar legítimas.
- `node_exporter` (~20 MB Go binary): legítimo de Prometheus, no malware.

## IOC conocidos a buscar
- `/etc/ld.so.preload` con contenido → rootkit userland.
- `/sbin/kthreadd*64` o `/usr/sbin/kthreadd*` → **siempre** anómalo (el `kthreadd` real es PID 2 del kernel).
- `/sbin/Xorg.X*`, `/sbin/busybox` descargado por dropper.
- C2 sobre puertos 143/110/443 disfrazados.
- Usuario creado por atacante: `rpcd`, `mysql`, `nginx`, `_*` como nombres de servicio falsos.

## Buenas prácticas DFIR
- **Modo solo-lectura TODO el tiempo durante la colección**: NO matar procesos, NO borrar archivos, NO remediar.
- Toda salida a filesystem externo de evidencia (`tee` a archivo preservado).
- Documentar cada comando con hora + host (cadena de custodia).
- Hashear (`sha256sum`) cada artefacto binario recolectado.
- Capturar entorno de proceso **antes** que cualquier otra cosa (`/proc/<pid>/{maps,cmdline,comm,exe,status,environ}`).
- Mantener imagen de disco original aparte si es posible (dd + ewfacquire).

## Referencias
- RFC 3227 (BCP 36): Guidelines for Evidence Collection and Archiving
- NIST SP 800-86: Integrating Forensic Techniques into Incident Response
- SANS DFIR Poster "Linux Forensics"
- Curtis Colwell / Linuxleo: Linux Forensics Quick Reference
- MITRE ATT&CK Enterprise Linux matrix
- `man 5 proc`, `man ld.so`, `man journalctl`
