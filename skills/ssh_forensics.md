# Skill: SSH Forensics

## Objetivo
Investigar evidencia forense asociada a SSH en un host Linux comprometido: llaves autorizadas, configuración de sshd, log de autenticación (Accept passwords, publickeys, sourceIPs. Detectar login inicial, llaves maliciosas y password/backdoor.

## Cuándo usarla
- Compromise Assessment (el vector inicial en hosts Linux suele ser SSH).
- Detectar nuove keys in authorized_keys o login foráneo.
- Auditar configuración de hardening TK autocницт.

## Comandos

### Lectura de authorized_keys (T1078 / T1098)
```bash
ls -la /root/.ssh/ ; ls -la /home/*/.ssh/
cat -n /root/.ssh/authorized_keys
ssh-keygen -lf /root/.ssh/authorized_keys       # fingerprints de todas las llaves
# Sólo llaves ACTIVAS (no comentadas con #):
grep -vE '^#|^$' /root/.ssh/authorized_keys | awk '{print $1,$3}'
# Comparar con backups:
ls -la /root/.ssh/authorized_keys*
diff /root/.ssh/authorized_keys.<oldest> /root/.ssh/authorized_keys
for f in /root/.ssh/authorized_keys.*; do echo "### $f"; ssh-keygen -lf "$f" 2>/dev/null; done
```

### usuarios con authorized_keys
```bash
for u in $(awk -F:'$7 ~ /(bash|sh)$/ {print $1}' /etc/passwd); do
  H=$(eval echo "~$u")
  [ -f "$H/.ssh/authorized_keys" ] && echo "### $u -> $H/.ssh/authorized_keys" && cat "$H/.ssh/authorized_keys"
done
```

### sshd config
```bash
cat /etc/ssh/sshd_config
ls -la /etc/ssh/sshd_config.d/ ; for f in /etc/ssh/sshd_config.d/*;do echo "## $f"; cat "$f";done
# Params relevantes
sshd -T                              # efectiva runtime config, requires reloading? no leída disabled
grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractive|AllowUsers|AllowGroups|Match|AuthorizedKeysFile|PermitEmptyPasswords|X11Forwarding|AllowTcpForwarding|PermitTunnel)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*
ls -la /etc/ssh/ssh_host_* /etc/ssh/ssh_ca.pub /etc/ssh/auth_principals 2>/dev/null     # CA & SSH certificates
```

### logs de autenticación
```bash
grep -hE "Accepted|Failed|Invalid|Disconnected|useradd|usermod|sudo.*:" /var/log/auth.log /var/log/auth.log.1 | grep -v repeated
# Por sourceIP foráneo:
grep -hE "Accepted (publickey|password|keyboard-interactive)" /var/log/auth.log /var/log/auth.log.1 | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | sort | uniq -c | sort -nr | head
# Por fingerprint de llave:
grep -hE "Accepted publickey" /var/log/auth.log /var/log/auth.log.1 | sed -n 's/.*SHA256:\([A-Za-z0-9/+]*\).*/SHA256:\1/p' | sort | uniq -c
# Logins root exitosos:
grep -hE "Accepted (publickey|password|keyboard-interactive/pam) for root" /var/log/auth.log /var/log/auth.log.1
# Sesiones por user y source IP:
last -F | awk '$1!="reboot"{print $1,$3}' | sort | uniq -c
# IP extranjeras (fuera del rango de la empresa):
last -F | awk '$1=="root"{print $3}' | sort | uniq -c
# Failed logins:
lastb -F | head -50
```

### Cron context antes/después del access
```bash
journalctl --since "2026-08-04 10:30" --until "2026-08-04 11:30" 2>/dev/null | grep sshd
```

## Interpretación
- `last -F` da hora, IP y duración de sesiones. Útil para correlacionar con `auth.log`.
- `auth.log` diferencia 3 métodos de autenticación:
  - `Accepted publickey` → llave SSH.
  - `Accepted password` → password (vía `PasswordAuthentication yes`).
  - `Accepted keyboard-interactive/pam` → keyboard-interactive a través de PAM (puede ser password, OTP, etc.). Para una backdoor user con `PasswordAuthentication=no` overall pero `KbdInteractiveAuthentication=yes` + `UsePAM=yes`, las passwords vienen por aquí.
- `PermitRootLogin prohibit-password` -> root sólo por llave. Un `Accepted password for root` AFTER de este setting es imposible (si no se hizo manualmente override).
- Llaves en `authorized_keys` que NO están en backups significan inserciones posteriores que pueden ser atacante.
- Diferencia entre comentario de llave (`4h1g4L0w4@proton.me`) y la realidad del operador: la fingerprint se usa muchas veces desde una IP geoconfiable - admin personal.
- SSH certificates (firmato CA) tienen ID con `@dominio`. Útil en enterprises con CA SSH (e.g. step-ca, Teleport).
- `lastb` failed logins - si naked brute force desde bots, normal. Si atinado de un IP pequeño rango → podría ser credential stuffing.

## Falsos positivos
- Llaves personales de admin con comment tipo `4h1g4L0w4@proton.me` leetspeak son admins.
- Sesiones root `keyboard-interactive/pam` desde IPs de la empresa son admins de confianza con password fijo OTP.
- Failed login de bots — en miles — para root, es ruido normal.

## IOC específicos
- `Accepted publickey for root from <AWS US-west IP>` con fingerprint RSA no visto en backups anteriores → vector inicial.
- Usuario "rpcd" (no estándar) creados y luego logins `keyboard-interactive/pam` → backdoor user.
- Llaves con comment unicode/raro o @protonmail sin identidad legítima correlatable.
- SSH host keys removed/regenerated (rc.local was reprogramming dpkg-reconfigure openssh-server).
- Comment `PermitRootLogin yes` or `PasswordAuthentication yes`.

## Buenas prácticas
- Hacer un "baseline" de fingerprints esperados por usuario (lista blanca): config mismucho custodied.
- Forzar `PasswordAuthentication no` + `KbdInteractiveAuthentication no` o OTP via PAM (OATH/TOTP/Duo).
- `PermitRootLogin prohibit-password` (solo llaves) MIENTI: usarías `PermitRootLogin no` directamente y sudo para validos.
- Instalar `google-authenticator` para 2FA SSH (`ChallengeResponseAuthentication yes`).
- Log sshd verybosity `LogLevel VERBOSE` para capturar fingerprints (already default en modern OpenSSH).
- Rotatekeys cada 90 días para admins y empliego auditable `etckeeper`.
- banned fail2ban para limitar ruido.
- Enrolling `ssh-keygen -lf` automatizado de authorized_keys en pipeline alertando llaves nuevas/arbitrarias.

## Referencias
- man 5 sshd_config, man 8 sshd.
- MITRE ATT&CK T1078 (Valid Accounts), T1110 (Brute Force), T1098 (Account Manipulation), T1136 (Create Account), T1021.004 (Remote Services: SSH).
- OpenSSH hardening guide https://www.ssh-audit.com.
- `last`, `lastb`, `aureport -au` (auditd) commands.
- Debian/Ubuntu `pam-auth-update` framework.