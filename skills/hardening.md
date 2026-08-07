# Skill: Hardening (Endurecimiento) Linux - CIS Benchmarks

## Objetivo
Comparar la configuración de un host Linux contra los controles CIS Benchmarks (CIS Ubuntu 22.04) para detectar permisos incorrect, users innecesarios, configuraciones insecure, secret泄露, servicios expuestos y credenciales tiradas.

## Cuándo usarla
- Al final de un Compromise Assessment (sección hardening).
- Como baseline post-remediación para prevenir re-infection.
- Auditoría sistemática de conformidad CIS.

## Sections recomendadas (CIS Ubuntu Linux v2.0)

### 1. Initial Setup
```bash
cat /etc/os-release; uname -r
apt list --installed 2>/dev/null | wc -l
# AIDE / file integrity:
dpkg -l | grep -E 'aide|tripwire|osquery|wazuh'
# SecureBoot:
sudo mokutil --sb-state 2>/dev/null
# Kernel parameters hardening:
sudo sysctl -a 2>/dev/null | grep -E "kernel.randomize_va_space|kernel.kptr_restrict|kernel.dmesg_restrict|kernel.perf_event_paranoid|fs.suid_dumpable|net.ipv4.conf.all.send_redirects|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.rp_filter|net.ipv4.tcp_syncookies"
```

### 2. Servicios innecesarios (CIS 2.x)
```bash
systemctl list-unit-files --state=enabled
# Disabling services commonly unsafe by default:
for svc in avahi-daemon cups nfs rpcbind ypserv dnsmasq snmpd slapd nginx vsftpd ftp lirc rsh-server telnet; do
  systemctl is-enabled "$svc" 2>/dev/null
done
```

### 3. SSH (CIS 5.x)
```bash
grep -E "^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol|MaxAuthTries|ClientAliveInterval|X11Forwarding|AllowTcpForwarding|AllowUsers|AllowGroups|IgnoreRhosts|HostbasedAuthentication|PermitTunnel|KbdInteractiveAuthentication)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
```
Recommendations:
- `PermitRootLogin no` (prefer, en lugar de `prohibit-password`).
- `PasswordAuthentication no`.
- `KbdInteractiveAuthentication no` (o usar 2FA).
- `MaxAuthTries 3`, `ClientAliveInterval 300`, `ClientAliveCountMax 0`.
- `IgnoreRhosts yes`, `HostbasedAuthentication no`.
- `PermitEmptyPasswords no`.
- Remove X11Forwarding unless needed.

### 4. Cuentas / Políticas de Password (CIS 6.x)
```bash
grep -E "PASS_" /etc/login.defs
chage -l root ; for u in $(awk -F:'$3>=1000 {print $1}' /etc/passwd); do chage -l $u; done
pam-config --print 2>/dev/null || grep -rE "pam_pwquality|pam_tally2|pam_faildelay" /etc/pam.d/
# Usuarios UID 0 sólo root:
awk -F:'$3==0 {print $1}' /etc/passwd
# Empty passwords:
awk -F: '$2=="" || $2=="!" {print $1, $2}' /etc/shadow
# Inactive accounts:
useradd -D | grep INACTIVE
```

### 5. Sudo / Privilege Escalación (CIS 5.x sudo)
```bash
cat /etc/sudoers; ls -la /etc/sudoers.d/; for f in /etc/sudoers.d/*; do cat $f; done
grep -rE "NOPASSWD|ALL=\(ALL" /etc/sudoers /etc/sudoers.d/*
# Use `sudo` requires password:
# `%sudo ALL=(ALL:ALL) NOPASSWD:ALL` → NO recomendado.
```

### 6. Permisos filesystem (CIS 1.x)
```bash
stat -c '%n %a %U:%G' /etc/passwd /etc/shadow /etc/group /etc/gshadow /boot/grub/grub.cfg
# Should: passwd 644, shadow 640 (shadow:shadow), group 644, gshadow 640, grub.cfg 400
find / -xdev -type f -perm -4000   # SUID list
find / -xdev -type f -perm -2000   # SGID list
getcap -r / 2>/dev/null            # capabilities
# Sticky world-writable dirs:
find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
# /tmp on separate partition with nodev,nosuid,noexec:
mount | grep -E "\b/tmp\b|\b/var/tmp\b"
```

### 7. Cron Restringido
```bash
ls -la /etc/cron* /var/spool/cron
cat /etc/cron.allow /etc/cron.deny 2>/dev/null   # should have allow list
```

### 8. Logging/audit (CIS 4.x)
```bash
dpkg -l | grep -E 'rsyslog|auditd|syslog-ng'
systemctl is-active rsyslog auditd
cat /etc/audit/auditd.conf 2>/dev/null
# auditd rules
ls -la /etc/audit/rules.d/ ; augenrules --check 2>/dev/null
# rsyslog remoto
grep -rE "@@|@.*514" /etc/rsyslog.conf /etc/rsyslog.d/
```

### 9. Kernel modules / USB restrictions
```bash
modprobe -c | head
echo "install usb-storage /bin/true" >> /etc/modprobe.d/no-usb.conf
# CIS recomienda deshabilitar cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf via modprobe.d
```

### 10. Secretos/credos expuestos (caza de tiros)
```bash
grep -rE "^(password|passwd|api_key|secret|token|private_key|client_secret)" /etc /opt /root /home /var/www 2>/dev/null | head -50
grep -rEi "BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY|---BEGIN PRIVATE KEY" /etc /opt /root /home 2>/dev/null
find / -xdev -name ".env" -o -name ".npmrc" -o -name ".pgpass" -o -name "credentials" -o -name ".netrc" 2>/dev/null
# Tokens leaked en crons:
grep -hE "Bearer|Authorization: Bearer|api_key|access_token" /var/spool/cron/crontabs/* /etc/cron.d/* 2>/dev/null
# SSH agent differences:
file /root/.ssh/id_*
```

### 11. Exposición de servicios (escucha en 0.0.0.0)
```bash
ss -tulnp | awk '$5 ~ /0\.0\.0\.0:|\[::\]:|:\*/ {print}'
# Deberían estar behind reverse proxy/firewall secciones only necesling:
# redis (6379), memcached (11211), mongo (27017), elastic (9200), jenkins (8084), grafana (3001), prometheus (9090), docker-proxy (3000-9000).
```

### 12. Firewall
```bash
ufw status verbose; iptables -L -n -v | head -30; nft list ruleset | head -50
# Default INPUT policy DROP es ideal.
# OUTPUT filter: inspiration permissive default → allow, except strict (CIS recommends).
```

### 13. Time sync & NTP
```bash
timedatectl; systemctl is-active systemd-timesyncd chronyd ntpd
```

### 14. Clave GPG
```bash
ls -la /etc/apt/trusted.gpg.d/ /etc/apt/sources.list
apt-key list 2>/dev/null | head -50          # 3rd party repos
```

## Interpretación / Riesgos mapeados
- `PermitRootLogin prohibit-password` → root puede loguearse con llave. Mejor `no` (uso de sudo).
- `PasswordAuthentication yes` → Brute force gravit primitive.
- `KbdInteractiveAuthentication yes` → si PAM permite passwords, backdoor users con keyboard-interactive bypass PasswordAuthentication=no setting. Configurar `pam_unix` deny si se quiere pure keyless.
- `NOPASSWD:ALL` en grupo sudo → Any compromised sudo account = instant root.
- Usuarios UID==0 fuera de root → directa falla CIS.
- Tokens/Authorization Bearing en crontabs → secret exposure Cleartext.
- Servicios en `0.0.0.0:6379` (Redis) sin Auth → disaster exposish.
- Auditd deshabilitado → no hay trail post-incidente.

## IOC específicos de hardening pentest
- `/etc/ld.so.preload` con contenido (deberia no existir → rootkit).
- `PermitRootLogin yes`, `PasswordAuthentication yes` en backup sshd_config bs administrate.
- Tokens `Authorization: Bearer 045e...` en crontabs (logged plaintext).
- `chmod 644 /etc/shadow` - world readable shadow.
- `/tmp` mounted `rw` sin `noexec,nodev,nosuid`.

## Buenas prácticas
- Apply CIS Level 1 baseline + Level 2 in servers de producción.
- Harden con `usg` (Ubuntu Security Guide): `apt install usg && usg fix --level=1` (auto CIS remediation).
- SSH hardening: `PermitRootLogin no`; `PasswordAuthentication no`; `KbdInteractiveAuthentication no` (except OTP).
- Use SSH certificates (step-ca, Teleport) ~ elimina authorized_keys management.
- Rotate SSH keys / service tokens / API keys cada 90d; use Vault / SOPS for secrets.
- `pam_tally2` or `pam_faillock` lock accounts after N failed attempts.
- Add `auditd` rules for `ld.so.preload`, `/etc/passwd`, `/etc/sudoers`, watch.
- Set `net.ipv4.conf.all rp_filter=1`, `tcp_syncookies=1`, accept_redirects=0 RP_filter strict.
- Egress firewall ostia pools de minado /known bad domains.
- Disable unused services: `systemctl disable rpcbind.dockerLXD`.
- Generate new SSH host keys if compromise confirmed (`dpkg-reconfigure openssh-server`).
- Jering all default creds / `apt purge telnet, rsh-client`/netcat/usr-bin.

## Referencias
- CIS Benchmarks Ubuntu Linux 22.04 v2.0.0 - Centre for Internet Security.
- Ubuntu Security Guide (usg) and `usg fix`.
- Lynis (`apt install lynis && lynis audit system`) - open source CIS-like audit.
- NIST SP 800-53 AC, IA, SC controls.
- Mozilla SSH Guidelines.
- `man 5 login.defs`, `man 8 auditctl`, `man 5 modprobe.d`, `man sshd_config`.
- Essential Linux hardening guides: NSp Linux HardSec.