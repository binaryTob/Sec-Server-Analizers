# Skill: Linux Forensics

## Objetivo
Recolectar, preservar y analizar evidencia de un sistema Linux comprometido **sin alterar el estado del sistema** (modo solo-lectura), siguiendo metodología profesional de DFIR.

## Cuándo usarla
- Cuando se sospecha o confirma un compromiso en un host Linux.
- Cuando se necesita realizar un Compromise Assessment.
- Antes de remediar para no contaminar la evidencia.

## Principio fundamental: Orden de Volatilidad (RFC 3227 BCP 36)
Recolectar primero lo más volátil: memoria → conexiones de red → procesos → sysctl/rutas → /proc → logs → filesystem.

## Comandos por etapa

### 1. Contexto del sistema (LO/FV)
```bash
cat /etc/os-release; uname -a; uptime; date; last reboot | head
who -b; arch; lscpu | head; free -h; uptime
```

### 2. Procesos y memoria
```bash
ps -eo pid,ppid,user,lstart,etime,pcpu,pmem,comm,args --sort=-pcpu | head -40
ps -eo pid,ppid,user,pmem,rss,vsz,args --sort=-rss | head -30
# Procesos cuyo binario fue borrado pero sigue cargado (deleted-but-open)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
# Diferencia ps vs /proc (detección de procesos ocultos)
echo "ps: $(ps -e --no-headers|wc -l) proc: $(ls -d /proc/[0-9]* 2>/dev/null|wc -l)"
# Procesos ejecutándose desde /tmp, /dev/shm, /var/tmp
ps -eo pid,user,args | grep -E "/tmp|/dev/shm|/var/tmp"
# Mapa de memoria de un PID sospechoso
cat /proc/<pid>/maps; cat /proc/<pid>/cmdline | tr '\0' ' '; cat /proc/<pid>/status
ls -la /proc/<pid>/cwd /proc/<pid>/exe /proc/<pid>/fd
```

### 3. Red
```bash
ss -tulnp                              # listeners
ss -tunp state established            # conexiones activas
ss -tan state established | awk '{print $5}' | sort -u   # destinos
ip -br a; ip -br link
cat /etc/hosts; cat /etc/resolv.conf
iptables -L -n -v; iptables -t nat -L -n -v
nft list ruleset                       # if nftables
```

### 4. Persistencia (revisar exhaustivamente)
```bash
# Cron
ls -la /etc/cron* ; cat /etc/crontab
for f in /etc/cron.d/*; do echo "### $f"; cat "$f"; done
crontab -l ; for u in $(awk -F: '$7 ~ /sh$/ {print $1}' /etc/passwd); do crontab -u $u -l; done
ls -laR /var/spool/cron/

# systemd
systemctl list-unit-files --state=enabled
systemctl list-units --type=service --state=running
systemctl list-timers --all
ls -laR /etc/systemd/system/

# shell rc
cat /root/.bashrc /root/.profile /etc/profile; ls -la /etc/profile.d/
cat /etc/rc.local; ls -la /etc/rc*.d /etc/init.d/

# SSH
ls -la /root/.ssh/; cat /root/.ssh/authorized_keys
ssh-keygen -lf /root/.ssh/authorized_keys
cat /etc/ssh/sshd_config; ls -la /etc/ssh/sshd_config.d/ ; cat /etc/ssh/sshd_config.d/*

# sudo/PAM
cat /etc/sudoers ; ls -la /etc/sudoers.d/ ; for f in /etc/sudoers.d/*;do cat $f;done
cat /etc/ld.so.preload ; ls -la /etc/ld.so.preload
getcap -r / 2>/dev/null
awk -F: '($2=="" || $2=="!") {print $1}' /etc/shadow
```

### 5. Caza de IOC en filesystem
```bash
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -4000  # SUID
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -xdev -type f -perm -2000  # SGID
find /tmp /var/tmp /dev/shm -type f -exec file {} \; | grep -iE 'elf|executable|script'
find /etc -mtime -7 -type f      # archivos modificados últimas 7d
# depósito de clave de persistencia:
grep -rEi "xmrig|kinsing|kdevtmpfsi|cnrig|minerd|cryptonight|stratum|monero|localhost0\.xyz|teamtnt|perfctl|redtail|rocke|sysrv" /etc/ /root/ /var/spool/cron/ 2>/dev/null
```

### 6. Logs
```bash
journalctl --since "YYYY-MM-DD HH:MM" --until "YYYY-MM-DD HH:MM"
grep -E "Accepted|Failed|Invalid|useradd|usermod|sudo|su:" /var/log/auth.log /var/log/auth.log.1
last -F | head -40 ; lastb -F | head -20
grep -iE "error|panic|segfault|out of memory" /var/log/syslog /var/log/kern.log
```

### 7. Verificación de integridad de paquetes
```bash
dpkg --verify        # Ubuntu/Debian: ??5 = md5 mismatch (modificado)
dpkg -S <archivo>     # archivo pertenece a paquete?
debsums -c           # verificación MD5 de todos los archivos de paquetes
rpm -Va              # RHEL/CentOS/Fedora equivalente
```

## Interpretación
- Procesos con `(deleted)` en `/proc/*/exe` → binario borrado pero cargado (típico de malware en ejecución).
- `ps != /proc` → posible rootkit LKM o namespace confusion (re-validar).
- Archivos SUID/SGID fuera de los estándar del OS (newgrp, passwd, sudo, su, mount, umount, pkexec, gpasswd, chsh, chfn, fusermount, ssh-agent, chage, crontab, expiry, dotlockfile, unix_chkpwd, postdrop, postqueue) → investigar.
- Cualquier línea añadida en `cron`, systemd, `.bashrc` o `/etc/ld.so.preload` → fuerte IOC de persistencia.
- `dpkg --verify` marcado `??5` → archivo modificado vs paquete (puede ser benigno en conffiles, p.e. /etc/default/*).

## Falsos positivos comunes
- chkrootkit "14 process hidden for ps": típicamente una race condition con procesos efímeros (sshd, cron, ps itself). Re-validar con un segundo escaneo en frío.
- ifpromisc marca a `systemd-networkd` como sniffer: es un daemon legítimo de red, FP.
- `dpkg --verify` flags conffiles modificados por admin (jenkins.service, motd-news): FP frecuente.
- `getcap` en `/usr/bin/ping` y `/usr/bin/mtr-packet`: capabilities estándar y legítimas.
- `node_exporter` (Go binary ~20 MB): legítimo de Prometheus; no es malware aunque parezca "estrangero".

## IOC conocidos a buscar
- `/etc/ld.so.preload` con contenido → rootkit userland (kthreadd32.so, libprocesshider.so).
- `/sbin/kthreadd*64` o `/usr/sbin/kthreadd*` mimetizando hilo del kernel (`/usr/sbin/kthreadd` real es del kernel; binarios con ese nombre en el FS son **siempre** anómalos).
- `/sbin/Xorg.X*`, `/sbin/busybox` descargado por un dropper.
- C2 sobre puertos 143/110/443 disfrazados.
- Usuario creado por atacante: `rpcd`, `mysql`, `nginx`, `_*`: falsos nombres de servicio new account.

## Buenas prácticas DFIR
- **Modo solo-lectura TODO el tiempo durante la colección**: NO matar procesos, NO borrar archivos, NO remediar hasta finalizar.
- Toda salida a un filesystem externo de evidencia (`tee` a archivo preservado).
- Documentar cada comando con hora + host (chain of custody).
- Hashear (`sha256sum`) cada artefacto binario recolectado.
- Capturar el entorno IN-VOLATILE primero (`/proc/<pid>/{maps,cmdline,comm,exe,status,environ}`).
- Re-capturar artefactos en movimiento en orden de volatilidad.
- Mantener imagen de disco original aparte si es posible.

## Referencias
- RFC 3227 (BCP 36) — Guidelines for Evidence Collection and Archiving (orden de volatilidad).
- NIST SP 800-86 — Integrating Forensic Techniques into Incident Response.
- SANS DFIR Poster "Linux Forensics".
- Curtis Colwell / Linuxleo — Linux Forensics Quick Reference.
- MITRE ATT&CK Enterprise Linux matrix.
- `man 5 proc`, `man ld.so`, `man journalctl`.