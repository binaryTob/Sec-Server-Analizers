---
id: "remote_readonly_triage"
name: "Skill: Remote Readonly Triage (SSH)"
version: "2.0"
category: "forensics"
phase: "collect"
risk: "readonly"
execution_mode: "auto"
depends_on: []
provides: ["incident_response", "hardening"]
triggers:
  - "Sospecha de compromiso en un host Linux al que NO se debe escribir nada"
  - "Compromise Assessment remoto de un servidor accesible solo por SSH"
  - "Triage inicial de un VPS/cloud donde no querés alterar el filesystem del target"
mitre_attack:
  - "N/A (colección forense remota solo-lectura)"
parameters:
  HOST:
    type: "string"
    required: true
    description: "IP o hostname del servidor remoto a analizar"
  PORT:
    type: "integer"
    default: 22
    required: false
    description: "Puerto SSH del host remoto"
  USER:
    type: "string"
    default: "root"
    required: false
    description: "Usuario SSH para conectar"
  SSH_ARGS:
    type: "string"
    default: ""
    required: false
    description: "Argumentos extra para ssh (ej: -i /ruta/key). Nunca hardcodear credenciales."
  OUTPUT_DIR:
    type: "filepath"
    default: "./forensic-remote-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio LOCAL (máquina del analista) donde se guarda la evidencia. NUNCA en el host remoto."
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
    description: "Ventana temporal de inicio para logs (journalctl --since)"
output:
  format: "json"
  schema: "output_schema"
---

# Skill: Remote Readonly Triage (SSH)

## Objetivo
Ejecutar un Compromise Assessment completo contra un host Linux **por SSH**, capturando toda la evidencia **localmente** en la máquina del analista y **sin escribir ni un solo byte en el servidor remoto**. Cumple RFC 3227 (no alterar el estado del sistema) y permite triage seguro de VPS/cloud.

## Cuándo usarla
- Sospecha de ataque/infección/mal-funcionamiento en un host Linux accesible por SSH.
- Cuando NO se debe modificar el target (regla de oro: solo-lectura).
- Como wrapper remoto del workflow `compromise_assessment`.

## Por qué esta skill (diferencia con las demás)
El resto de las skills asumen ejecución **local** y guardan evidencia con `tee`/`cp` dentro del propio host comprometido, lo que viola la regla de no-alteración. Esta skill redirige todo el tráfico de salida a un `OUTPUT_DIR` **local**, usando un wrapper SSH que ejecuta cada bloque vía `bash -s` remoto (stdin) sin tocar el filesystem del target.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{HOST}}` | string | sí | — | IP/hostname del servidor remoto |
| `{{PORT}}` | integer | no | `22` | Puerto SSH |
| `{{USER}}` | string | no | `root` | Usuario SSH |
| `{{SSH_ARGS}}` | string | no | `""` | Args extra de ssh (key, opts). No hardcodear credenciales |
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio LOCAL de evidencia |
| `{{SINCE}}` | datetime | no | `1 day ago` | Inicio de ventana para logs |

## Pre-flight (validación + wrapper SSH)

```bash
# [risk:info] [mode:auto]
command -v ssh >/dev/null 2>&1 || { echo "ERROR: ssh no disponible localmente"; exit 1; }
mkdir -p "$OUTPUT_DIR"

# Wrapper: ejecuta un script solo-lectura en el host remoto vía stdin (bash -s).
# Nada de lo que corra acá escribe en el target: todo el output vuelve a la máquina local.
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new ${SSH_ARGS}"
remote() {
  ssh ${SSH_OPTS} -p "${PORT}" "${USER}@${HOST}" bash -s
}

# Test de conectividad (readonly). Si falla, aborta sin tocar nada.
remote <<'EOF' > "$OUTPUT_DIR/00_connectivity.txt" 2>&1
echo "=== CONNECTIVITY $(date -Iseconds) ==="
hostname
uname -a
id
date -Iseconds
uptime
EOF
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ERROR: no se pudo conectar a ${USER}@${HOST}:${PORT}"
  cat "$OUTPUT_DIR/00_connectivity.txt"
  exit 1
fi
cat "$OUTPUT_DIR/00_connectivity.txt"
```

## Comandos (todos readonly sobre el target)

### 1. Contexto del sistema
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/01_system_context.txt"
echo "=== OS ==="; head -5 /etc/os-release
echo "=== UPTIME ==="; uptime
echo "=== DATE ==="; date -Iseconds
echo "=== LAST REBOOT ==="; last reboot | head -5
echo "=== CPU ==="; lscpu | head -12
echo "=== MEM ==="; free -h
echo "=== DISK ==="; df -h
echo "=== LOAD ==="; cat /proc/loadavg
EOF
```

### 2. Procesos y memoria (volátil)
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/02_processes.txt"
echo "=== TOP CPU ==="; ps -eo pid,ppid,user,lstart,etime,pcpu,pmem,comm,args --sort=-pcpu | head -40
echo "=== TOP RSS ==="; ps -eo pid,ppid,user,pmem,rss,args --sort=-rss | head -25
echo "=== PS vs /proc COUNT ==="; echo "ps=$(ps -e --no-headers | wc -l) proc=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
echo "=== FROM /tmp /dev/shm /var/tmp ==="; ps -eo pid,user,args | grep -E "/tmp|/dev/shm|/var/tmp" | grep -v grep
echo "=== DELETED-BUT-OPEN EXE ==="; ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
EOF
```

### 3. Red (listeners, conexiones, rutas)
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/network_state.txt"
echo "=== LISTENERS ==="; ss -tulnp
echo "=== ESTABLISHED ==="; ss -tnp state established
echo "=== UNCOMMON LISTENERS ==="; ss -tulnp | grep -vE ':(22|80|443) '
echo "=== INTERFACES ==="; ip -br a
echo "=== ROUTES ==="; ip route show
echo "=== FIREWALL (nft) ==="; nft list ruleset 2>/dev/null | head -60
echo "=== FIREWALL (iptables) ==="; iptables -L -n -v 2>/dev/null
EOF
```

### 4. Persistencia: cron
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/03_cron.txt"
echo "=== /etc/crontab ==="; cat /etc/crontab 2>/dev/null
echo "=== /etc/cron.d ==="; for f in /etc/cron.d/*; do [ -f "$f" ] && echo "### $f" && cat "$f"; done
echo "=== cron dirs ==="; ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
echo "=== spool ==="; ls -laR /var/spool/cron/ 2>/dev/null
echo "=== root crontab ==="; crontab -l 2>/dev/null
EOF
```

### 5. Persistencia: systemd + timers
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/04_systemd.txt"
echo "=== ENABLED UNITS ==="; systemctl list-unit-files --state=enabled 2>/dev/null
echo "=== RUNNING SERVICES ==="; systemctl list-units --type=service --state=running --no-pager 2>/dev/null
echo "=== FAILED SERVICES ==="; systemctl list-units --type=service --state=failed --no-pager 2>/dev/null
echo "=== TIMERS ==="; systemctl list-timers --all --no-pager 2>/dev/null
echo "=== /etc/systemd/system tree ==="; ls -laR /etc/systemd/system/ 2>/dev/null | head -150
EOF
```

### 6. Persistencia: rc, shell rc, ld.so.preload, módulos
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/05_autostart.txt"
echo "=== /etc/ld.so.preload ==="; cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.preload 2>/dev/null
echo "=== /etc/ld.so.conf.d ==="; cat /etc/ld.so.conf.d/*.conf 2>/dev/null
echo "=== custom .so in /usr/local/lib ==="; ls -la /usr/local/lib/*.so* 2>/dev/null
echo "=== /etc/rc.local ==="; cat /etc/rc.local 2>/dev/null
echo "=== /root/.bashrc (tail) ==="; tail -40 /root/.bashrc 2>/dev/null
echo "=== /root/.profile ==="; cat /root/.profile 2>/dev/null
echo "=== /etc/profile.d ==="; ls -la /etc/profile.d/ 2>/dev/null
echo "=== /etc/environment ==="; cat /etc/environment 2>/dev/null
echo "=== modules-load.d ==="; ls -la /etc/modules-load.d/ 2>/dev/null; cat /etc/modules-load.d/* 2>/dev/null
EOF
```

### 7. Usuarios y cuentas
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/06_users.txt"
echo "=== UID 0 users ==="; grep -E ':x:0:' /etc/passwd
echo "=== users with shell ==="; grep -E '/(bash|sh)$' /etc/passwd
echo "=== non-system users (uid>=1000) ==="; awk -F: '$3>=1000 && $3<65534 {print}' /etc/passwd
echo "=== passwords set (shadow) ==="; awk -F: '($2!="*" && $2!="!" && $2!="!!" && $2!="") {print $1":HASH_SET"}' /etc/shadow
echo "=== sudo group ==="; getent group sudo admin wheel 2>/dev/null
echo "=== sudoers NOPASSWD ==="; grep -rE 'NOPASSWD|ALL=\(ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
echo "=== useradd/usermod in logs ==="; grep -hE 'useradd|usermod|chpasswd' /var/log/auth.log* 2>/dev/null | tail -30
EOF
```

### 8. SSH (llaves, config, CA)
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/07_ssh.txt"
echo "=== root .ssh ==="; ls -la /root/.ssh/ 2>/dev/null
echo "=== authorized_keys (con comentarios) ==="; grep -vE '^#|^$' /root/.ssh/authorized_keys 2>/dev/null | awk '{print $1, $3}'
echo "=== fingerprints ==="; ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null
echo "=== authorized_keys backups ==="; ls -la /root/.ssh/authorized_keys* 2>/dev/null
echo "=== sshd_config (activo) ==="; grep -vE '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null
echo "=== sshd_config.d ==="; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
echo "=== effective sshd -T (key params) ==="; sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|usepam|allowusers|allowgroups|authorizedkeysfile|permitemptypasswords|x11forwarding|allowtcpforwarding|permittunnel|trustedusercakeys|authorizedprincipalsfile)'
echo "=== SSH CA ==="; cat /etc/ssh/ssh-ca.pub 2>/dev/null; ls -la /etc/ssh/auth_principals/ 2>/dev/null; cat /etc/ssh/auth_principals/* 2>/dev/null
EOF
```

### 9. Logs de autenticación
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/08_auth.txt"
echo "=== AUTH FILES ==="; ls -la /var/log/auth.log* 2>/dev/null
echo "=== ACCEPTED LOGINS ==="; grep -hE 'Accepted' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | tail -60
echo "=== SOURCE IPs (freq) ==="; grep -hE 'Accepted (publickey|password|keyboard-interactive)' /var/log/auth.log* 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | sort | uniq -c | sort -nr | head -20
echo "=== FAILED (count) ==="; grep -hcE 'Failed password' /var/log/auth.log /var/log/auth.log.1 2>/dev/null
echo "=== INVALID USERS ==="; grep -hE 'Invalid user' /var/log/auth.log* 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | sort | uniq -c | sort -nr | head -20
echo "=== SUDO ==="; grep -hE 'sudo:|su:' /var/log/auth.log* 2>/dev/null | tail -30
echo "=== LAST ==="; last -F | head -40
echo "=== LASTB ==="; lastb -F 2>/dev/null | head -30
echo "=== LASTLOG ==="; lastlog 2>/dev/null | grep -v 'Never logged'
EOF
```

### 10. Caza de malware (filesystem y firmas)
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/09_malware.txt"
echo "=== EXECUTABLES EN TEMP ==="; find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -40
echo "=== HIDDEN DIRS /tmp ==="; ls -la /tmp/ 2>/dev/null | head -30
echo "=== NOMBRES DE MALWARE CONOCIDOS ==="; find / -xdev -type f \( -name 'kthreadd*' -o -name 'Xorg.X*' -o -name '*xmrig*' -o -name 'kdevtmpfsi' -o -name 'cnrig*' -o -name 'minerd*' -o -name 'systemd-update' -o -name 'libprocesshider*' -o -name 'kinsing' \) 2>/dev/null
echo "=== WALLETS CRYPTO ==="; grep -rE '4[A-Za-z0-9]{94}|8[A-Za-z0-9]{94}|0x[a-f0-9]{40}|bc1[q0-9][a-z0-9]{39,59}' /etc /root /var/spool/cron 2>/dev/null | grep -v moduli | head -20
echo "=== SUID/SGID ==="; find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
echo "=== STRINGS MINERIA EN CONFIGS ==="; grep -rlEi 'xmrig|stratum|donate-level|cryptonight|--coin=monero|pool\.' /etc /root /var/spool/cron 2>/dev/null
EOF
```

### 11. Rootkit (ld_preload, procesos ocultos, LKM, integridad)
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/10_rootkit.txt"
echo "=== LD.SO.PRELOAD ==="; cat /etc/ld.so.preload 2>/dev/null
echo "=== LD_PRELOAD EN /proc ==="; for p in /proc/[0-9]*/environ; do grep -l LD_PRELOAD "$p" 2>/dev/null; done
echo "=== HIDDEN PROCS (ps vs /proc) ==="; ps_count=$(ps -e --no-headers | wc -l); proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l); echo "ps=$ps_count proc=$proc_count diff=$((proc_count-ps_count))"
echo "=== LSMOD ==="; lsmod
echo "=== MODULE SIGNERS ==="; for m in $(awk '{print $1}' /proc/modules); do sig=$(modinfo "$m" 2>/dev/null | grep -i signer); echo "$m : ${sig:-NO-SIGNER}"; done
echo "=== DPKG VERIFY (coreutils) ==="; dpkg --verify 2>/dev/null | grep -E '(ps|ls|ss|top|netstat|find)$'
echo "=== DEBSUMS ==="; debsums -c 2>/dev/null | grep -E '/(ps|ls|top|ss|netstat|find)$'
EOF
```

### 12. Mal-funcionamiento (servicios caídos, errores, OOM)
```bash
# [risk:ro] [mode:auto]
remote <<'EOF' | tee "$OUTPUT_DIR/11_malfunction.txt"
echo "=== FAILED UNITS ==="; systemctl list-units --type=service --state=failed --no-pager 2>/dev/null
echo "=== JOURNAL ERR (24h) ==="; journalctl -p err --since "24 hours ago" --no-pager 2>/dev/null | tail -60
echo "=== OOM / PANIC / SEGFAULT ==="; grep -iE 'oom|kill|panic|segfault|hung task' /var/log/kern.log /var/log/syslog 2>/dev/null | tail -30
echo "=== DISK INODES ==="; df -ih
EOF
```

<!-- MODULE:helpers.extract_iocs_network -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- `ps != /proc` → posible rootkit LKM (re-validar en idle: FP por procesos efímeros).
- `(deleted)` en `/proc/*/exe` con binarios del sistema (agetty, python, logind) tras un `apt upgrade` → benigno. Con binarios de `/tmp` o nombres raros → malware.
- `/etc/ld.so.preload` con contenido → rootkit userland (T1547.007).
- `Accepted password for root` con `PasswordAuthentication yes` → superficie de brute force real.
- `systemctl` con unidades `enabled` pero `inactive` (ej: wazuh-agent) → gap de monitoreo/seguridad.
- Journal lleno de `etcdserver: request timed out` / `failed to find member` → cluster etcd inestable (no es malware, es operativo).
- IPs de login que NO sean de infra propia → pivote a `log_analysis` con `SUSPECT_IP`.

## Falsos positivos
- Binarios `(deleted)` de servicios del SO tras updates.
- `awk`/`grep` que matchean `/etc/ssh/moduli` (primos Diffie-Hellman) como "wallets" → siempre filtrar con `grep -v moduli`.
- `systemd-networkd`/`systemd-resolved` marcados como sniffer por chkrootkit → legítimos.
- `Failed password` de bots contra root → ruido; foco en `Accepted` y en IPs no corporativas.

## Buenas prácticas
- **Nunca** ejecutar acciones de contención/erradicación desde esta skill: es estrictamente solo-lectura.
- Guardar `OUTPUT_DIR` local y hashear al final (cadena de custodia) — ya incluido vía `helpers.hash_evidence`.
- Usar `SSH_ARGS="-i ~/.ssh/id_ed25519"` para autenticar por clave; no dejar claves en el repo.
- Re-correr en idle para descartar FPs de `ps != /proc`.
- Si se confirma compromiso, migrar a `incident_response` (que sí contiene acciones `cont`/`erad`, con confirmación).

## Referencias
- RFC 3227 (BCP 36): Guidelines for Evidence Collection and Archiving
- NIST SP 800-86: Integrating Forensic Techniques into Incident Response
- MITRE ATT&CK Enterprise Linux matrix
- `man ssh`, `man 5 sshd_config`
- Repo Server-Analizers: skills `linux_forensics`, `ssh_forensics`, `cryptominer_detection`, `malware_hunting`, `rootkit_detection`, `persistence_detection`, `log_analysis`, `IOC_hunting`
