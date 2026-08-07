# Skill: Rootkit Detection en Linux

## Objetivo
Detectar rootkits de usuario (userland, LD_PRELOAD T1547.007), rootkits de kernel (LKM T1014), y técnicas de ocultación de procesos/archivos en un host Linux comprometido.

## Cuándo usarla
- Procesos que no aparecen en `ps` pero sí en `/proc`.
- `/proc/<pid>/exe` apunta a `(deleted)` o a una ruta inexistente.
- chkrootkit/rkhunter reportan "process hidden" o "Possible LKM Trojan".
- En todo Compromise Assessment como rutina.

## Comandos

### Detección de LKM rootkits (T1014)
```bash
lsmod
cat /proc/modules
modinfo <module>            # módulos sin "signer" son sospechosos
cat /proc/kallsyms | awk '$3=="t" || $3=="T"' | head    # tabla de syscalls
# Verificar módulos firmados (Debian/Ubuntu requieren Secure Boot):
for m in $(awk '{print $1}' /proc/modules); do
  sig=$(modinfo "$m" 2>/dev/null | grep -i signer)
  echo "$m : ${sig:-NO-SIGNER}"
done
# Comparar con la lista de módulos cargados esperada por el sistema
```

### Detección de LD_PRELOAD userland (T1547.007)
```bash
cat /etc/ld.so.preload                  # SIEMPRE debe estar vacío o no existir en distros estándar
ls -la /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/
ls -la /usr/local/lib/*.so /lib/x86_64-linux-gnu/*.so 2>/dev/null
# Verificar que el preload no esté activo en procesos vivos:
for p in /proc/[0-9]*/environ; do
  if grep -q LD_PRELOAD "$p" 2>/dev/null; then
    echo "$p"; tr '\0' '\n' < "$p" | grep LD_PRELOAD
  fi
done
# Encontrar hooks en la lib sospechosa:
strings -a /usr/local/lib/kthreadd32.so 2>/dev/null | grep -Ei "readdir|opendir|__lxstat|lstat|readlink|closedir|unlink|processhider|hide|proc"
# Patrón clásico: el rootkit hookea readdir para que /sbin/kthreadd64 no aparezca en /proc
file /usr/local/lib/kthreadd32.so ; sha256sum /usr/local/lib/kthreadd32.so
```

### Detección de procesos ocultos
```bash
ps_count=$(ps -e --no-headers | wc -l)
proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
echo "ps=$ps_count proc=$proc_count"   # si difieren → probable rootkit
# Comparar listas de PIDs:
diff <(ls /proc | grep -E '^[0-9]+$' | sort -n) <(ps -e --no-headers | awk '{print $1}' | sort -n)
# Procesos cuyo binario fue borrado pero sigue cargado:
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
for p in /proc/[0-9]*; do
  link=$(readlink "$p/exe" 2>/dev/null)
  case "$link" in
    *deleted*|"") : ;;
    *) case "$link" in
         /tmp/*|/dev/shm/*|/var/tmp/*) echo "PID ${p#/proc/}: $link";;
       esac;;
  esac
done
# Binary replaced vs dpkg original md5:
dpkg --verify 2>/dev/null | grep -E "ps$|ls$|ss$|top$|netstat$|ifconfig$" 
debsums -c 2>/dev/null | grep -E "/(ps|ls|top|ss|netstat)$"
```

### rkhunter (recommended scanner)
```bash
which rkhunter
rkhunter --update
rkhunter --check --skip-keypress --report-warnings-only
# Logs: /var/log/rkhunter.log
# Config: /etc/rkhunter.conf
# Whitelisted known-good:
#   SCRIPTWHITELIST=/usr/bin/lsof
#   USER_FILEPROP_FILES=/etc/passwd:/etc/group:/etc/sudoers
# FP mitmenschen: ALLOWHIDDENFILE=/usr/local/lib/*.so
```

### chkrootkit
```bash
which chkrootkit
chkrootkit                                            # full scan
chkrootkit -l                                         # list tests
chkproc                                              # hidden process detection
chkdirs                                              # hidden directory detection
# Output relevante:
#   Checking `ldsopreload'...           not infected    (valida /etc/ld.so.preload)
#   Checking `lkm'... Possible LKM Trojan + N process hidden
#   Checking `sniffer'... eth0 PACKET SNIFFER(...)
```

### aux tools
```bash
which unhide; unhide-linux brute       # hunting de procesos ocultos
which tiger                            # otro auditor
which checksec                         # verifica mitigaciones del kernel
which aide                             # file integrity monitoring baseline
which osquery; osqueryi "select * from process_open_files where path like '/tmp/%';"
which lynis; lynis audit system        # CIS-like audit
```

## Interpretación
- `/etc/ld.so.preload` debe estar vacío o no existir. Si tiene una entrada → rootkit userland: la librería listada hookeará glibc para esconder archivos/procesos (típica `libprocesshider.so`, `kthreadd32.so`). Allí el atacante instala un subrootkit para ocultar al miner.
- Hooks típicos a buscar dentro de la lib: `readdir`, `readdir64`, `opendir`, `lstat`, `__xstat`, `readlink`, `unlink`, `filefilldir`.
- Hidden processes en `ps != /proc` → LKM rootkit o race condition / namespace confusion (FP).
- chkrootkit "Possible LKM Trojan installed" + "N process hidden" → raaza condicion con procesos efímeros (cron, ps itself, mforks sshd). FP MUY común; re-validar en frío o sin carga.
- ifpromisc FP sobre `systemd-networkd[NN]` (`/usr/lib/systemd/systemd-networkd`) → no es sniffer malicioso, es el daemon legítimo de networking.
- `dpkg --verify`報告 `??5??????` sobre `/bin/ps` ó `/usr/bin/top` → binario reemplazado por rootkit.

## IOC de rootkits conocidos
- `libprocesshider.so` (GitHub: jordan-ja, originalmente PoC didáctico).
- `kthreadd32.so`, `kthreadd.so`, `libs.so`, `libsys.so` en `/usr/local/lib`, `/lib` o `/usr/local/lib/x86_64-linux-gnu`.
- `kdevtmpfsi` + `/proc/2/exe` modified (PID 2 del kernel normalmente no mapeado a file).
- Módulos en `/proc/modules` con `LICENSE` no estándar / sin signer.
- `nulled` binarios en `/bin` con permisos extraños.
- En el caso concreto de este informe: `/usr/local/lib/kthreadd32.so`, fuente descargada de `http://localhost0.xyz/kthreadd32.c`, compilada con `gcc -Wall -fPIC -shared -o kthreadd32.so kthreadd32.c -ldl` e instalada vía `echo /usr/local/lib/kthreadd32.so >> /etc/ld.so.preload`.

## Falsos positivos
- chkrootkit "process hidden for readdir" con mucha carga → race con procesos efímeros. Re-correr en idle.
- rkhunter FP en módulos con `unhide` "Possibly hardened kernel".
- `systemd-networkd[NN]` marcado como PACKET SNIFFER legitimo.
- `dpkg --verify` marca conffiles modificados por admin (jenkins.service, motd-news): FP frecuente.
- binarios `(deleted)` en `/proc/*/exe` con PID corta vida (cron jobs) no son malware.

## Buenas prácticas
- Restringir carga de módulos kernel: `/etc/modprobe.d` allowlist + Secure Boot enforced (dm-verity).
- Mantener `ps`, `ls`, `top`, `netstat`, `ss` originales y verificados con `debsums -c`.
- File Integrity Monitoring con AIDE (`apt install aide && aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db`).
- MAC enforcing: AppArmor profiles estrictos para limitar escritura en `/usr/local/lib`.
- `auditctl` rules para monitorizar `openat("/etc/ld.so.preload")` y `setuid` desde usuarios no root:
  ```
  auditctl -w /etc/ld.so.preload -p wa -k preload_watch
  auditctl -w /usr/local/lib -p wa -k lib_watch
  auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k modules
  ```
- CIS 1.x baseline mantiene /etc sin chmod exótico usable.
- Reinstalar paquetes sospechosos: `apt install --reinstall coreutils procps net-tools`

## Referencias
- MITRE ATT&CK T1014 (Rootkit - LKM), T1547.007 (ld.so.preload), T1574.006 (Dynamic Linker Hijacking), T1562.001 (disable tools).
- chkrootkit: https://github.com/Magentron/chkrootkit
- rkhunter: https://rkhunter.sourceforge.net/
- "Linux Userland Rootkits" by Null Byte / LiveOverflow talks.
- libprocesshider PoC: https://github.com/jordan-ja/libprocesshider
- `man 8 ld.so` (definición de `/etc/ld.so.preload`, `rpath`).
- Linux Kernel Runtime Guard (LKRG) - https://lkrg.org
- Kernel Self Protection Project (KSPP) recomendaciones.