# Skill: Persistence Detection en Linux

## Objetivo
Enumerar exhaustivamente los mecanismos de persistencia usados por atacantes en un host Linux: cron, systemd, init, rc.local, shell rc, SSH, PAM, LD_PRELOAD, sudoers,Authorized_keys, kernel modules.

## Cuándo usarla
- Siempre en un Compromise Assessment (presencia confirma que sobrevivirá a reboot).
- Tras detectar malware o backdoor user, para enumerar todos los puntos que dejó el atacante.

## Comandos: enumerar cada vector T1547/T1053/T1136

### systemd (T1543.002, T1053.006 timers)
```bash
systemctl list-unit-files --state=enabled
systemctl list-units --type=service --state=running
systemctl list-units --type=service --state=failed
systemctl list-timers --all
ls -laR /etc/systemd/system/
find /etc/systemd /lib/systemd/system -mtime -90 -type f
# Drop-in overrides (T 摄 clásicas):
systemctl cat <svc>          # muestra todos los override drop-ins
ls -la /etc/systemd/system/*.d/ /etc/systemd/system/*/override.conf
# Generators path exploitation:
ls /etc/systemd/system-generators/ /usr/lib/systemd/system-generators/
```

### cron (T1053.003)
```bash
cat /etc/crontab
ls -la /etc/cron* ; for f in /etc/cron.d/*;do echo "### $f"; cat "$f";done
ls -la /etc/cron.{hourly,daily,weekly,monthly}
crontab -l  ; for u in $(awk -F:'$7~/sh$/{print $1}' /etc/passwd); do crontab -u $u -l; done
ls -laR /var/spool/cron /var/spool/anacron /var/spool/at
atq ; at -c <id>
# Cron systemdTimerlock typo:
grep -rE "(\*/[0-9]+\s\*\s\*\s\*\s\*\s+root\s+/[a-z])" /etc/cron*   # detectar entradas muy frecuentes
```

### rc.local / init.d / rc*.d (T1037.004, T1547.006)
```bash
cat /etc/rc.local
ls -la /etc/rc*.d /etc/init.d/
diff /etc/init.d/sshd /usr/lib/init.d/sshd.bak   # modified scripts
ls -la /etc/modules-load.d/* /etc/modprobe.d/*          # kernel modules autoloading (T1547.006 LKMs)
```

### shell rc / profiles (T1547.004)
```bash
cat /etc/profile /etc/bash.bashrc
ls -la /etc/profile.d/ ; cat /etc/profile.d/*.sh
cat /root/.bashrc /root/.bash_profile /root/.profile /root/.bash_login
for u in root examen-carnet test examenes jenkins mark-hdr; do
  echo "### $u"; cat /home/$u/.bashrc /home/$u/.profile 2>/dev/null
done
cat /etc/environment ; cat /root/.bash_aliases
```

### SSH (T1098, T1078, T1136)
```bash
ls -la /root/.ssh/ ; ls -la /home/*/.ssh/
cat /root/.ssh/authorized_keys ; ssh-keygen -lf /root/.ssh/authorized_keys
for u in $(awk -F:'$7~/sh$/{print $1}' /etc/passwd); do
  f=$(eval echo "~$u")/.ssh/authorized_keys
  [ -f "$f" ] && echo "### $u" && cat "$f"
done
# Backups de authorized_keys (timestamp indica cuando se editó):
ls -la /root/.ssh/authorized_keys*
# Diff contra backup para detectar llaves nuevas/eliminadas:
diff /root/.ssh/authorized_keys.20260424-184336 /root/.ssh/authorized_keys
# Llapas nuevas -> calcular fecha de incorporación y fingerprint
cat /etc/ssh/sshd_config ; ls /etc/ssh/sshd_config.d/ ; cat /etc/ssh/sshd_config.d/*
# Llaves de host - no deben ser removidas accidentalmente:
ls -la /etc/ssh/ssh_host_*
```

### sudoers / PAM (T1548.003)
```bash
cat /etc/sudoers
ls -la /etc/sudoers.d/ ; for f in /etc/sudoers.d/*;do echo "### $f"; cat "$f";done
grep -rE "NOPASSWD|ALL=\(ALL" /etc/sudoers /etc/sudoers.d/*
# Usuarios que ahora pueden hacer sudo (group sudo/admin/wheel)
getent group sudo admin wheel
ls -la /etc/pam.d/ ; cat /etc/pam.d/sshd /etc/pam.d/su /etc/pam.d/common-auth
```

### Backdoor users (T1136.001)
```bash
awk -F: '$3>=1000 && $3<65534 {print}' /etc/passwd
awk -F: '($2!="*" && $2!="!" && $2!="!!") {print $1,$2,$3}' /etc/shadow   # usuarios con password setteado
chage -l <user>        # última vez que se cambió el password (anómalo recente)
grep -E "useradd|usermod" /var/log/auth.log /var/log/auth.log.1
# Skeleton/backdoor common service names: rpcd, mysql, nginx, sshd, www
for u in rpcd mysql nginx sshd www-data postgres; do
  id $u 2>/dev/null && grep "^$u:" /etc/passwd
done
```

### LD_PRELOAD / libraries (T1547.007, T1574.006)
```bash
cat /etc/ld.so.preload ; ls -la /etc/ld.so.preload
ls -la /usr/local/lib/*.so /usr/local/lib/*.so.*
cat /etc/ld.so.conf ; ls /etc/ld.so.conf.d/ ; cat /etc/ld.so.conf.d/*.conf
grep -rE "LD_PRELOAD" /etc /root /home 2>/dev/null
# preload activo en procesos vivos - check sus /proc/PID/envs
for p in /proc/[0-9]*/environ; do grep -l LD_PRELOAD $p 2>/dev/null; done
```

### Activación automática de servicios (systemctl enable / preset)
```bash
systemctl list-unit-files --state=enabled --type=service
# presets permitidos por distro vs servicios habilitados
systemctl preset --dry-run \*.service 2>/dev/null
```

## Interpretación
- `*/5 * * * * root /sbin/Xorg.X13 55` cron.d absurdamente frecuente para algo "de sistema" → IOC.
- Usuario nuevo (UID 1000-65000) con shell asociado fuera de lo normal → investigar historial.
- Hash de password md5 (`$1$`) en usuario de servicio → técnico atacante seteó pass débil.
- Líneas `NOPASSWD:` en sudoers → generalmente inseguro, revisar si fue añadido por el atacante.
- `.bashrc` con aliases/sourced de paths inusuales (p.e. `source /tmp/.cache/.bashrc`) → backdoor shell rc.
- `~/.ssh/authorized_keys` con ed25519 públicos desconocidos y versión backups → añadir/eliminar por atacante.
- `/etc/ld.so.preload` con contenido (file > 0 bytes) → sospecha alta de rootkit userland.
- Backups datados authorized_keys.*: comparar período en que se insertó la llave nueva.
- Acceso vía `pwent_check` (sudo u asus) al registro last: si roll登陆 logins de IP foránea con método dropper (`keyboard-interactive` para servicio sin shell).

## Falsos positivos
- Donweb/empresa: van agregando/removiendo ed25519 de employeds authorized_keys常常 — diff chronológico por fecha para distinguir.
- `NOPASSWD`-sudo para deployments ansible/jenkins → legit en infra-as-code.

## IOC específicos comunes
- `/etc/cron.d/certbot` con línea no estándar.
- `/etc/ld.so.preload` apuntando `/usr/local/lib/kthreadd32.so`.
- Usuario `rpcd`, `mysql`, `_sys_*`.
- Llaves ed25519 con comment protonmail raros en root authorized_keys.
- Drop-in overrides en `/etc/systemd/system/docker.service.d/` que agregan `ExecStartPost=...`.

## Buenas prácticas
- Snapshot git/etckeeper de /etc -> diffing automático de /etc para notar cambios. Considera instalar `etckeeper`.
- Endurecer PAM (negar passwords débiles con `libpam-pwquality`), disminuir `PermitRootLogin prohibit-password`, `PasswordAuthentication no`.
- Hacer `globetrotter` checklist de autostart: `sysdigi`/`linuxploit` offers good overview tool.
- Revisar `/etc/updatedb.conf` y `/etc/modprobe.d/*`—escondite común.

## Referencias
- MITRE ATT&CK T1547 - Boot or Logon Autostart Execution.
  - T1543.002 systemd, T1543.002 init.d, T1053.003 cron, T1037.004 rc.local, T1547.004 shell rc ssh rot, T1547.007 ld.so.preload, T1548.003 sudo, T1136 user creation.
- "Linux Persistence Techniques" Trail of Bits https://github.com/trailofbits/auditd.
- `chkrootkit`, `rkhunter`, `lynis` systematic audit tools.
- `etckeeper` for /etc git history.