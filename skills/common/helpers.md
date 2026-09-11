# Common Helpers — Módulo de funciones reutilizables

Módulos compartidos que pueden ser inyectados (`<!-- MODULE:helpers.nombre -->`) en cualquier skill.
Cada helper acepta parámetros y está taggeado con nivel de riesgo y modo de ejecución.

---

## helper:collect_volatile
**Descripción**: Recolecta evidencia volátil de procesos en orden de volatilidad RFC 3227.
**Parámetros**: `OUTPUT_DIR`, `PID` (opcional)

```bash
# [risk:ro] [mode:auto] [module:collect_volatile]
{
  echo "=== COLLECT_VOLATILE $(date -Iseconds) ==="
  ps -eo pid,ppid,user,lstart,etime,pcpu,pmem,comm,args --sort=-pcpu
  ss -tulnp
  ss -tnp state established
  ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
  echo "ps_count=$(ps -e --no-headers | wc -l) proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
} > "{{OUTPUT_DIR}}/volatile.txt"
```

---

## helper:collect_process_detail
**Descripción**: Extrae toda la información forense de un PID específico.
**Parámetros**: `OUTPUT_DIR`, `PID` (requerido)

```bash
# [risk:ro] [mode:auto] [module:collect_process_detail] [requires:PID]
P="{{PID}}"
D="{{OUTPUT_DIR}}"
mkdir -p "$D/proc-$P"
for f in cmdline comm status environ maps exe cwd fd; do
  ls -la "/proc/$P/$f" 2>/dev/null > "$D/proc-$P/$f"
done
readlink "/proc/$P/exe" > "$D/proc-$P/exe_link"
cat "/proc/$P/cmdline" | tr '\0' ' ' > "$D/proc-$P/cmdline_decoded"
cp "$(readlink /proc/$P/exe)" "$D/proc-$P/binary" 2>/dev/null
sha256sum "$D/proc-$P/binary" > "$D/proc-$P/binary.sha256" 2>/dev/null
```

---

## helper:collect_network_state
**Descripción**: Recolecta estado completo de red del host.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:collect_network_state]
D="{{OUTPUT_DIR}}"
{
  echo "=== NETSTATE $(date -Iseconds) ==="
  ss -tulnp
  echo "--- ESTABLISHED ---"
  ss -tnp state established
  echo "--- INTERFACES ---"
  ip -br a; ip -br link
  echo "--- ROUTES ---"
  ip route show
  echo "--- DNS ---"
  cat /etc/resolv.conf
  echo "--- FIREWALL ---"
  iptables -L -n -v 2>/dev/null
  nft list ruleset 2>/dev/null
} > "$D/network_state.txt"
```

---

## helper:collect_persistence_vectors
**Descripción**: Enumera todos los vectores de persistencia conocidos.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:collect_persistence_vectors]
D="{{OUTPUT_DIR}}"
mkdir -p "$D/persistence"
cp /etc/crontab "$D/persistence/crontab" 2>/dev/null
cp -r /etc/cron.d "$D/persistence/cron.d" 2>/dev/null
cp -r /etc/cron.hourly "$D/persistence/cron.hourly" 2>/dev/null
cp -r /etc/cron.daily "$D/persistence/cron.daily" 2>/dev/null
systemctl list-unit-files --state=enabled > "$D/persistence/systemd_enabled.txt"
systemctl list-timers --all > "$D/persistence/systemd_timers.txt"
ls -laR /etc/systemd/system/ > "$D/persistence/systemd_units.txt"
cat /etc/ld.so.preload > "$D/persistence/ld.so.preload" 2>/dev/null
cat /etc/rc.local > "$D/persistence/rc.local" 2>/dev/null
cat /root/.bashrc > "$D/persistence/root_bashrc" 2>/dev/null
cat /etc/profile > "$D/persistence/etc_profile" 2>/dev/null
ls -la /etc/profile.d/ > "$D/persistence/profile.d.txt" 2>/dev/null
```

---

## helper:collect_auth_logs
**Descripción**: Extrae eventos de autenticación relevantes de auth.log y journal.
**Parámetros**: `OUTPUT_DIR`, `SINCE` (default: "1 day ago")

```bash
# [risk:ro] [mode:auto] [module:collect_auth_logs]
D="{{OUTPUT_DIR}}"
S="{{SINCE:-1 day ago}}"
{
  echo "=== AUTH LOGS $(date -Iseconds) ==="
  grep -hE "Accepted|Failed|Invalid|useradd|usermod|sudo:" /var/log/auth.log* 2>/dev/null
  echo "--- LAST ---"
  last -F
  echo "--- LASTB ---"
  lastb -F
  echo "--- JOURNAL AUTH ---"
  journalctl --since "$S" --facility auth 2>/dev/null
} > "$D/auth_events.txt"
```

---

## helper:hash_evidence
**Descripción**: Genera hashes SHA256 de toda la evidencia recolectada para cadena de custodia.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:hash_evidence]
cd "{{OUTPUT_DIR}}" && sha256sum $(find . -type f | sort) > evidence.sha256
```

---

## helper:extract_iocs_network
**Descripción**: Extrae IOCs de red desde la evidencia capturada.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:extract_iocs_network]
D="{{OUTPUT_DIR}}"
{
  echo "type,value,context"
  grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$D/network_state.txt" 2>/dev/null \
    | sort -u | while read ip; do echo "ipv4-addr,$ip,extracted from network capture"; done
  grep -oE '[a-zA-Z0-9.-]+\.[a-z]{2,}' "$D/network_state.txt" 2>/dev/null \
    | sort -u | while read dom; do echo "domain-name,$dom,extracted from network capture"; done
} > "$D/iocs_network.csv"
```

---

## helper:scan_malware_signatures
**Descripción**: Busca firmas de malware conocidas en el filesystem por nombre de archivo.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:scan_malware_signatures]
{
  echo "=== MALWARE SIGNATURE SCAN $(date -Iseconds) ==="
  find / -xdev -type f \( \
    -name 'kthreadd*' -o -name 'Xorg.X*' -o -name '*xmrig*' \
    -o -name 'kdevtmpfsi' -o -name 'cnrig*' -o -name 'systemd-update' \
    -o -name 'kinsing' -o -name 'libprocesshider*' -o -name 'kthreaddi' \
  \) 2>/dev/null | while read f; do
    echo "PATH: $f"
    file "$f" 2>/dev/null
    sha256sum "$f" 2>/dev/null
    echo "---"
  done
} > "{{OUTPUT_DIR}}/malware_scan.txt"
```

---

## helper:verify_binaries
**Descripción**: Verifica integridad de binarios del sistema contra dpkg/rpm.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:verify_binaries]
{
  echo "=== BINARY INTEGRITY $(date -Iseconds) ==="
  dpkg --verify 2>/dev/null | grep -v "c /"
  debsums -c 2>/dev/null
  rpm -Va 2>/dev/null
} > "{{OUTPUT_DIR}}/binary_integrity.txt"
```

---

## helper:collect_ssh_artifacts
**Descripción**: Recolecta artefactos SSH: llaves autorizadas, config, host keys.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:ro] [mode:auto] [module:collect_ssh_artifacts]
D="{{OUTPUT_DIR}}"
mkdir -p "$D/ssh"
cp /etc/ssh/sshd_config "$D/ssh/sshd_config" 2>/dev/null
cp -r /etc/ssh/sshd_config.d "$D/ssh/sshd_config.d" 2>/dev/null
for u in $(awk -F:'$7 ~ /(bash|sh)$/ {print $1}' /etc/passwd); do
  H=$(eval echo "~$u")
  if [ -f "$H/.ssh/authorized_keys" ]; then
    mkdir -p "$D/ssh/$u"
    cp "$H/.ssh/authorized_keys" "$D/ssh/$u/authorized_keys"
    ssh-keygen -lf "$H/.ssh/authorized_keys" > "$D/ssh/$u/authorized_keys.fp" 2>/dev/null
  fi
done
```

---

## helper:block_c2_egress
**Descripción**: Bloquea tráfico saliente hacia IPs/dominios de C2 (contención).
**Parámetros**: `C2_IPS` (lista de IPs separadas por espacio)

```bash
# [risk:cont] [mode:confirm] [module:block_c2_egress] [requires:C2_IPS]
for ip in {{C2_IPS}}; do
  iptables -I OUTPUT -d "$ip" -j DROP 2>/dev/null
  echo "[CONTAINMENT] Bloqueada salida hacia $ip"
done
iptables -L OUTPUT -n -v | grep DROP
```

---

## helper:remove_malware_binaries
**Descripción**: Elimina binarios de malware conocidos del filesystem.
**Parámetros**: `MALWARE_PATHS` (lista de rutas separadas por espacio)

```bash
# [risk:erad] [mode:confirm] [module:remove_malware_binaries] [requires:MALWARE_PATHS]
for f in {{MALWARE_PATHS}}; do
  if [ -f "$f" ]; then
    sha256sum "$f" > "{{OUTPUT_DIR}}/removed_$(basename "$f").sha256" 2>/dev/null
    rm -f "$f"
    echo "[ERADICATION] Eliminado: $f"
  fi
done
```

---

## helper:clean_ld_preload
**Descripción**: Limpia /etc/ld.so.preload para desactivar rootkits userland.
**Parámetros**: `OUTPUT_DIR`

```bash
# [risk:erad] [mode:confirm] [module:clean_ld_preload]
cp /etc/ld.so.preload "{{OUTPUT_DIR}}/ld.so.preload.bak" 2>/dev/null
> /etc/ld.so.preload
echo "[ERADICATION] /etc/ld.so.preload limpiado"
```

---

## helper:disable_backdoor_user
**Descripción**: Bloquea y deshabilita un usuario backdoor.
**Parámetros**: `BACKDOOR_USER`

```bash
# [risk:cont] [mode:confirm] [module:disable_backdoor_user] [requires:BACKDOOR_USER]
usermod -L "{{BACKDOOR_USER}}" 2>/dev/null
usermod -s /usr/sbin/nologin "{{BACKDOOR_USER}}" 2>/dev/null
gpasswd -d "{{BACKDOOR_USER}}" sudo 2>/dev/null
echo "[CONTAINMENT] Usuario {{BACKDOOR_USER}} bloqueado y removido de sudo"
```

---

## helper:ssh_remote_exec
**Descripción**: Wrapper para ejecutar comandos **solo-lectura** en un host remoto vía SSH,
capturando el output localmente sin escribir nada en el target (RFC 3227).
**Parámetros**: `HOST` (requerido), `PORT` (default 22), `USER` (default root), `SSH_ARGS` (opcional)

```bash
# [risk:ro] [mode:auto] [module:ssh_remote_exec]
command -v ssh >/dev/null 2>&1 || { echo "ERROR: ssh no disponible"; exit 1; }
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new ${SSH_ARGS:-}"
remote() {
  ssh ${SSH_OPTS} -p "${PORT:-22}" "${USER:-root}@${HOST}" bash -s
}

# Uso: alimentar con un heredoc cuyo script corre en el remoto vía stdin.
# Todo el output regresa a la máquina local; no se escribe nada en el target.
#   remote <<'EOF' > evidencia_local.txt
#   echo "=== DATO ==="
#   <comandos readonly>
#   EOF
```

> Nota: `bash -s` lee el script desde stdin, de modo que los `$`, comillas simples y
> construcciones de `awk` se escriben tal cual (sin doble escape). No incluir jamás
> comandos `cont`/`erad`/`reconf` en un bloque `remote`.
