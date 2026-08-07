# Skill: Incident Response Linux - Workflow Profesional

## Objetivo
Definir el flujo end-to-end de Respuesta a Incidentes en host Linux siguiendo NIST SP 800-61 / SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned).

## Cuándo usarla
- Frente a un incidente confirmado (malware en ejecución, acceso unauthorized demonstrating active).
- Compromise Assessment con declinación IR activa.
- Sospecha fundada de intrusión.

## Reglas prt order rocedure (modo solo-lectura)
1. **Preparation**: tener herramienta lista, conectividad SSH, almacenamiento externo, plan escrito.
2. **Identification**: detectar el incidente, scope initial, alerta.
3. **Containment (short term)**: aísla el host (firewall egress block, VPN disconnect), NO reinsiciar primer vez para no perder volátil.
4. **Collection sólo lectura**: capturar evidencia de volátil → no volátil en orden orden volatilidad (RFC 3227).
5. **Containment (long term)**: disable account, block C2, snapshot disk.
6. **Eradication**: remove malware, clean persistence (LD_PRELOAD, cron, user backdoors).
7. **Recovery**: rebuild host from new image / re-provision, restore data from clean backup.
8. **Lessons Learned**: post-incident report, improve controls.

## 7 fases tácticas para un host Linux comprometido
```text
1. PRE - herramientas: sysstat, bin SOC, journal-dump, shasum, netcat Sinkhole incluido.  Ranura alcanze
2. IDENT - trigger host CPU high/network spike & vector inicial SSH
3. CONTABLE - firewall bloqueega C2 IP 89.117.109.224 ld_preload lib removida
4. COLLECT - ver linux_forensics.md (this repo)
5. ERADIC - eliminar /sbin/Xorg.X13 /sbin/busybox /sbin/kthreadd* /usr/local/lib/kthreadd32.so (+ preload); quitar rpcd de sudo; bloquear animo
6. RECOV - root password rotate; ssh host keys rotate; rotate creds  
7. POST - informar brut force trend, update HIDS rules
```

## Comandos secuencia (modo read-only)

### Fase 1: Collect forense volátil sin tocar
Capture solo lectura cada uno guardando en `/root/forensic-backup-YYYYMMDD/` (schema estándar).
```bash
ts=$(date +%Y%m%d-%H%M%S)
mkdir -p /root/forensic-backup-$ts
cd /root/forensic-backup-$ts

# Volátil
ps -eo pid,ppid,user,lstart,pcpu,pmem,args > ps.full         # procesos
ss -tulnp > ss_listen ; ss -tnp > ss_established              # red
ip a > ip.txt ; ip route > ip_route.txt
cat /etc/resolv.conf > resolv.conf
ls -la /proc/*/exe 2>/dev/null | grep deleted > deleted_exe  # deleted-but-open
lsmod > lsmod ; cat /proc/modules > proc_modules              # LKM
cat /etc/ld.so.preload > ld.so.preload; ls /usr/local/lib/*.so > usr_local_lib
uptime ; date > times

# Proceso sospechoso: capturar PID individual  
pid=<pid>
ls -la /proc/$pid/ > proc-$pid-dir
cat /proc/$pid/{cmdline,comm,status,environ,maps} > proc-$pid-{cmdline,comm,status,environ,maps}
readlink /proc/$pid/exe > proc-$pid-exe
ls -la /proc/$pid/fd/ > proc-$pid-fd
# COPIAR el binario (cp -a --no-preserve=ownership read-only):
cp $(readlink /proc/$pid/exe) proc-$pid-binary 2>/dev/null
sha256sum proc-$pid-binary > proc-$pid-binary.sha256

# Files relevant
cp -a /etc/crontab /etc/cron.d /var/spool/cron/crontabs /etc/cron.daily /etc/systemd/system /etc/ld.so.preload /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh . 2>/dev/null

# Logs
journalctl --since "1 day ago" > journal-1d.txt
cp /var/log/auth.log /var/log/auth.log.1 . 2>/dev/null
last -F > last.log ; lastb -F > lastb.log

# Hashing integrity
sha256sum $(find . -type f) > evidence.sha256
```

### Fase 2: triage / categorizar
```bash
# Hay un miner? (ver cryptominer_detection)
grep -- "--coin=monero" proc-*-cmdline
# Hay un LD_PRELOAD rootkit? (ver rootkit_detection)
grep kthreadd ld.so.preload
# Vectors de persistencia? (ver persistence_detection)
diff /etc/cron.d/certbot ../forensic-backup-prev/cron.d/certbot
```

### Fase 3: Containment - (es write; pedir autorización)
```bash
# Bloque egress al C2 (no mata procesos):
iptables -I OUTPUT -d 89.117.109.224 -j DROP
# Bloque backdoor user:
usermod -L rpcd ; usermod -s /usr/sbin/nologin rpcd
gpasswd -d rpcd sudo
# Comentar persistence cron:
sed -i.bak 's|^\*/5.*Xorg.X13 55|#*/5 * * * * root /sbin/Xorg.X13 55|' /etc/cron.d/certbot
```

### Fase 4: Eradication - (write)
```bash
# Remove malware binaries:
rm -f /usr/sbin/kthreadd64 /sbin/kthreadd64 /sbin/Xorg.X13 /sbin/busybox /usr/local/lib/kthreadd32.so
# Clear ld.so.preload:
> /etc/ld.so.preload
# Remove backdoor user:
userdel -r rpcd
# Rotate SSH keys:
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''
# Rotate root password:
passwd
# Harden sshd
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
# Remove unknown authorized_keys entries (compare with backup):
nano /root/.ssh/authorized_keys
```

### Fase 5: Recovery
- Rebuild host preferentemente desde una imagen nueva desplegada por IaC.
- Patch/upgrade all packages, disable unused services.
- Rotate application secrets tokens (DB, API keys).
- Restore data from verified clean backup.
- Monitor closely post-recovery (journalctl -f, auditd rules).

### Fase 6: Lessons Learned - Informe final
- Resumen ejecutivo, evidencias, IoCs, ATT&CK map, recoms, remediation plan.
- Avance control checkboxes:
  - [ ] forense preservado
  - [ ] host contained
  - [ ] malware removed
  - [ ] persistence vectors stripped
  - [ ] credentials rotated
  - [ ] logs rotated to SIEM
  - [ ] threat intel feed actualizado con новые IOCs
  - [ ] nuevo hardening baseline aplicado

## Escalación a Körper forensic external
Si el incidente es muy sophisticated, considerar:
- LiveCD / RedLine / Velociraptor offline.
- Imagen E01 con `dd` + `ewfacquire` / `FTK Imager for Linux`.
- Memory image `LiME module`, analizar con `volc`/`volatility3`.
- Subir binarios a MalwareBazaar con `abuse.ch` / VirusTotal.
- SSR with threat Intel (CrowdStrike, Mandiant).

## Falsos positivos
- Top CPU por `node /app/dist/main` (CI build normal).
- Brute force SSH from bots no == intrusion (sólo ruido).
- `chkrootkit` LKM false positives (race condition de procesos efímeros).

## IOC checklist (extender según evolución)
```
IP C2:        89.117.109.224
Pool:         143
Domain C2:    localhost0.xyz
Wallet XMR:   4B7vsy8ccUwQufi...
Worker email: sarapena7979@gmail.com
Backdoor user: rpcd (UID 1005)
Malware binaries:
  /sbin/Xorg.X13 (sh dropper, 1729 bytes)
  /sbin/busybox.static (downloader, 1034060 bytes)
  /sbin/kthreadd64 (XMRig, 8297712 bytes, sha256 b0e1ae6d73d656b203514f498b59cbcf29f067edf6fbd3803a3de7d21960848d)
  /usr/local/lib/kthreadd32.so (LD_PRELOAD rootkit, 16784 bytes)
Source IP attacker: 54.193.29.177 (AWS US-West California)
SSH RSA fp initial: SHA256:nz1L6wKzffgO0NumXgcS51pUaAQAYmA0rqDpKvqCfaU
Persistence:
  - /etc/ld.so.preload → /usr/local/lib/kthreadd32.so
  - /etc/cron.d/certbot → */5 * * * * root /sbin/Xorg.X13 55
  - rpcd user + sudo group
```

## Referencias
- NIST SP 800-61 R2 - Computer Security Incident Handling Guide.
- SANS PICERL framework - https://www.sans.org/white-papers/34967/.
- MITRE ATT&CK for Enterprise Linux.
- Linux Forensics Quick Reference - SANS DFIR poster.
- "Applied Incident Response" - Sammons.
- "The Practice of Network Security Monitoring" - Richard Bejtlich.