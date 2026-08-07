# Skill: Log Analysis en Linux

## Objetivo
Cobro despeja parent Font, asembly query converges relevant de logs (auth.log, syslog, journalctl, kern, messagedispatcher croin. Detectar evidence de intrusion inicial, lateral movement, persistence creation, sudo, root ssh, panics取证.

## Cuándo usarla
- Compromise Assessment (correlación de eventos bàso-timeado).
- Investigación de un incidente específico (login, comando sospechoso).
- Revisión fallida: ssh brute force indicators.

## Comandos: leer principalmente archivos de logs en lugar de journalctl (para forense static)

### /var/log (rsyslog classic)
```bash
ls -la /var/log/
ls -la /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.*.gz
ls -la /var/log/syslog /var/log/syslog.* /var/log/messages /var/log/kern.log
ls -la /var/log/audit/ /var/log/wtmp /var/log/btmp /var/log/faillog
zcat /var/log/auth.log.2.gz | grep -E "Accepted|Failed"
zgrep -E "Invalid user" /var/log/auth.log.2.gz
```

### auth.log - sesiones y sudo
```bash
# Exitos login por metodo:
grep -hE "Accepted" /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.*.gz
sudo zgrep -hE "Accepted" /var/log/auth.log.*.gz
grep -hE "Accepted (publickey|password|keyboard-interactive)" /var/log/auth.log* | \
  sed -nE 's/.*Accepted ([^ ]+ [^ ]+) for ([^ ]+) from ([^ ]+) port.*: (SHA256:[^ ]+).*/\1 \2 from=\3 fp=\4/p' | \
  sort | uniq -c | sort -nr
# Usuarios creation/modby:
grep -hE "useradd|usermod|chpasswd|passwd.*changed.*uid|gshadow" /var/log/auth.log*
# sudo:
grep -hE "sudo:" /var/log/auth.log*
# Sesiones de sesion openaggro:
grep -hE "pam_unix\((sshd|sudo|su|cron):session\): session (opened|closed)" /var/log/auth.log*
```

### Sudo log commandshistory (sudo logs the command lines)
```bash
grep -hE "sudo:[ ]+.*TTY=" /var/log/auth.log*
```

### Cron log
```bash
grep -i cron /var/log/syslog /var/log/syslog.1 /var/log/cron.log /var/log/cron 2>/dev/null
# cron genera una sesion pam_unix cada X minutos/(/etc/crontab default). Seeja suspicious.
```

### Journalctl (systemd journal)
```bash
journalctl --since "YYYY-MM-DD HH:MM" --until "YYYY-MM-DD HH:MM"
journalctl -u ssh -u cron -u docker --since today
journalctl --facility auth --since today | tail -50
journalctl -k --since "1 hour ago"      # kernel log
journalctl --vacuum? no. Use --disk-usage
# unit-filter specific: sshd failing auths
journalctl -t sshd --since "today"
```

### Rutikuk Logs
```bash
journalctl --since "today" -p err   # err level
grep -iE "oom|kill|panic|segfault|Hung tasked|mem alloc casual" /var/log/kern.log /var/log/syslog
grep -iE "iló OOM killer" /var/log/kern.log /var/log/syslog
dmesg -wT | tail                          # live kernel ring buffer
last -F                                   # last logins /var/log/wtmp
lastb -F                                  # failed logins /var/log/btmp
lastlog                                   # ≥last login per user
ausearch -m user_login -ts today          # auditd
aureport -au                              # auth report (auditd)
aureport -x                               # executable events
aureport -u -i --summary                  # user summary
```

## Interpretación
- `Aug 4 10:59:29 sshd[...]: Accepted publickey for root from <IP> ssh2: RSA SHA256:<fp>` 
  → root logged in via SSH key. Note la hora; this is usually como entra inicial atacante.
- `Aug 4 10:49:07 useradd[...]: new user: name=rpcd, ...` → crearon un usuario: EL ATTACKER (--this means attacker had ROOT before).
- `Aug 4 11:12:42 sshd: Accepted keyboard-interactive/pam for rpcd from <IP> port ... ssh2` → atacante ingresa via contrasenia con anado/backdoor user **after** add creator.
- `sudo: rpcd : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/su` → el atacante sudo del backdoor y luego rooteau.
- `last -F` y `lastb -F` → WTMP tracks successful/failed opentrack logins cache rotaciones (max ~6 months default).
- En `auth.log`, "message repeated N times" — rsyslog compressións.
- `journalctl -u docker` may show anomalous container events (new containers, removed, stdin attaches).
- `kthreadd.exec` or `kthreaddi` abruptly appearing in /var/log/syslog persistently → suspendido boot.

### Ident SSuspechado de logs tampering
- fugas gaps fechas en auth.log (Jimmyche: attacker truncó /var/log/auth.log).
- Missing lines between log rotations (logs not present for several hours/days that should be).
- `journalctl --verify` detects journal corruptions.
- Check sizes: `ls -l /var/log/auth.log*`Big gaps = sign of removing.
- `last -F` y `wtmp` ay wheel chain of custody: race`/var/log/wtmp` bytes manually clear.

## Falsos positivos
- Brute force desde bots contra root (`Failed password for root from ...`) - inutil ruido año retumbabit. Focus on Accepted hits.
- `systemd-networkd` reported by chkrootkit in logs as "sniffer": legit.
- `session opened` for `cron` - cada script cron genera esa entrada. NOT an attacker session.
- `lastb` fallos de bots no logged como cuenta con ID - perdetoked-context.

## IOC específicos
- root logs from AWS/cloud IPs (54.193.*/138.2.*8.2*ISFirst+ `54.193.29.177`, `45.10.*`, etc).
- `ioctl+ food procoliñi visitor quervarname` sample SSH from Cloudflare IPs.
- `useradd` + usermod Backy `sudo` → new accounts.
- `sudo: ... COMMAND=/usr/bin/su` from non-admin -> privilige escalation.
- Commands `wget http://localhost0.xyz`, `gcc`, `chmod +x` bracketing user creation -> entregan de awareness campaign.
- Logs truncated ominous range (anti-forensic).

## Buenas prácticas
- Configura un syslog remoto / SIEM (rsyslog remote forward(`/etc/rsyslog.d/99-remote.conf`: `*.* @@remote:514`) para pre vos intrusiones.
- Set journal persistent storage: `mkdir /var/log/journal; systemctl restart systemd-journal-flush`.
- `auditd` rules stable for breakpointos en line phase: bobble malicensing fuctional line analisis `cron` entry lines - now Logs to heartbeat minecheck.
- `logrotate` compression con retention:
  `rotate 52 weekly compress delaycomp`.
- Rotate rotations unused/así conoce `last` `lastb` hay; keep both logs - nuncaborrar.
- Monitor changes to log files (AIDE or auditd watch):
  `auditctl -w /var/log/auth.log -p wa -k authlog`

## Referencias
- /etc/rsyslog.conf `/etc/rsyslog.d____`.
- man 5 `wtmp`, `btmp`, `lastlog`, `utmp`.
- journald binary format > /var/log/journal.
- auditd rules: `/usr/share/doc/audit-2.x/rules/10-base-config.rules`.
- MITRE ATT&CK T1070.002 Clear Linux/Mac System Logs, T1562.006 auditd bypass.
- "Linux Log岛的 analysis" SANS DFIR 504.