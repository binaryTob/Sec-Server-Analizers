---
id: "incident_response"
name: "Skill: Incident Response Linux — Workflow Profesional"
version: "2.0"
category: "response"
phase: "contain"
risk: "destructive_containment"
execution_mode: "confirm"
depends_on:
  - "linux_forensics"
  - "cryptominer_detection"
  - "malware_hunting"
  - "rootkit_detection"
  - "persistence_detection"
  - "IOC_hunting"
  - "ssh_forensics"
  - "log_analysis"
provides: ["hardening"]
triggers:
  - "Incidente confirmado: malware en ejecución, acceso no autorizado activo"
  - "Compromise Assessment con declinación a IR activa"
  - "Sospecha fundada de intrusión"
mitre_attack:
  - "T1110"      # Brute Force
  - "T1078"      # Valid Accounts
  - "T1098.001"  # SSH key add
  - "T1136.001"  # Create Account
  - "T1059.004"  # Bash
  - "T1105"      # Ingress Tool Transfer
  - "T1027.002"  # Compile .c → .so
  - "T1547.007"  # ld.so.preload
  - "T1543.002"  # systemd
  - "T1053.003"  # cron
  - "T1496"      # Resource Hijacking
  - "T1571"      # Non-Standard Port
  - "T1070.002"  # Clear Logs
  - "T1562.006"  # auditd bypass
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio raíz para evidencia forense"
  C2_IPS:
    type: "string"
    default: ""
    required: false
    description: "IPs de C2 a bloquear (separadas por espacio)"
  BACKDOOR_USER:
    type: "string"
    default: ""
    required: false
    description: "Nombre del usuario backdoor a deshabilitar"
  MALWARE_PATHS:
    type: "string"
    default: ""
    required: false
    description: "Rutas de binarios de malware a eliminar (separadas por espacio)"
  CRON_BACKDOOR_FILE:
    type: "filepath"
    default: ""
    required: false
    description: "Archivo cron con entrada maliciosa a comentar"
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "ipv4-addr"
    value: "198.51.100.42"
    context: "Dirección sintética reservada para documentación; no es un IOC operativo"
    source: "synthetic-example"
    confidence: "high"
  - type: "ipv4-addr"
    value: "192.0.2.17"
    context: "Dirección sintética reservada para documentación; no es un IOC operativo"
    source: "synthetic-example"
    confidence: "high"
  - type: "domain-name"
    value: "example.invalid"
    context: "Dominio sintético reservado para documentación; no es un IOC operativo"
    source: "synthetic-example"
    confidence: "high"
  - type: "x-mono-wallet"
    value: "SYNTHETIC_WALLET_EXAMPLE"
    context: "Marcador sintético; no es una dirección de wallet"
    source: "synthetic-example"
    confidence: "high"
  - type: "email"
    value: "operator@example.invalid"
    context: "Marcador sintético; no es una identidad real"
    source: "synthetic-example"
    confidence: "medium"
  - type: "user"
    value: "synthetic-user"
    context: "Marcador sintético; no representa una cuenta real"
    source: "synthetic-example"
    confidence: "high"
  - type: "filepath"
    value: "/example/synthetic-dropper"
    context: "Ruta sintética de ejemplo; no identifica un archivo real"
    source: "synthetic-example"
    confidence: "high"
  - type: "file:sha256"
    value: "0000000000000000000000000000000000000000000000000000000000000000"
    context: "Hash sintético reservado para documentación; no es un IOC operativo"
    source: "synthetic-example"
    confidence: "high"
  - type: "filepath"
    value: "/example/synthetic-library.so"
    context: "Ruta sintética de ejemplo; no identifica un archivo real"
    source: "synthetic-example"
    confidence: "high"
---

# Skill: Incident Response Linux — Workflow Profesional

## Objetivo
Definir el flujo end-to-end de Respuesta a Incidentes en host Linux siguiendo NIST SP 800-61 / SANS PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned). Esta skill es el **orquestador**: invoca las skills especializadas en cada fase y ejecuta las acciones de contención y erradicación.

## Cuándo usarla
- Incidente confirmado: malware en ejecución, acceso no autorizado demostrando actividad.
- Compromise Assessment con declinación a IR activa.
- Sospecha fundada de intrusión.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de evidencia |
| `{{C2_IPS}}` | string | sólo tras validación | vacío | IOCs del caso actual; nunca usar valores de ejemplo |
| `{{BACKDOOR_USER}}` | string | sólo tras validación | vacío | Cuenta confirmada por evidencia del caso |
| `{{MALWARE_PATHS}}` | string | sólo tras validación | vacío | Rutas preservadas y verificadas del caso |
| `{{CRON_BACKDOOR_FILE}}` | filepath | sólo tras validación | vacío | Archivo confirmado por evidencia del caso |

## Reglas de orden de procedimiento
1. **Preparation**: herramienta lista, conectividad SSH, almacenamiento externo, plan escrito.
2. **Identification**: detectar el incidente, scope inicial, alerta.
3. **Containment (short term)**: aislar host (firewall egress block, VPN disconnect). **NO reiniciar** para no perder volátil.
4. **Collection solo-lectura**: capturar evidencia volátil → no volátil en orden de volatilidad (RFC 3227).
5. **Containment (long term)**: deshabilitar cuentas, bloquear C2, snapshot de disco.
6. **Eradication**: eliminar malware, limpiar persistencia (LD_PRELOAD, cron, backdoor users).
7. **Recovery**: rebuild host desde imagen nueva / re-provision, restore data de backup limpio.
8. **Lessons Learned**: informe post-incidente, mejorar controles.

## 7 fases tácticas (flujo ilustrativo; acciones destructivas requieren validación)
```
1. PRE  — herramientas: sysstat, bin SOC, journal-dump, shasum, netcat sinkhole
2. IDENT — trigger: CPU alta / network spike + vector inicial SSH
3. CONT  — firewall bloquea C2 IP, LD_PRELOAD removido
4. COLLECT — ver linux_forensics.md
5. ERAD  — eliminar dropper + miner + rootkit + usuario backdoor
6. RECOV — rotar root password; rotar SSH host keys; rotar credenciales de aplicación
7. POST  — informar brute force trend, actualizar reglas HIDS
```

## Comandos

### Fase 1: Collect forense volátil sin tocar (SOLO-LECTURA)
<!-- MODULE:helpers.collect_volatile -->
<!-- MODULE:helpers.collect_network_state -->
<!-- MODULE:helpers.collect_auth_logs -->
<!-- MODULE:helpers.collect_persistence_vectors -->
<!-- MODULE:helpers.collect_ssh_artifacts -->

```bash
# [risk:ro] [mode:auto]
# Fase de colección completa — ejecutar ANTES de cualquier acción de contención
D="${OUTPUT_DIR:?}"
umask 077
mkdir -p "$D"
ts=$(date +%Y%m%d-%H%M%S)

# --- Colección volátil completa ---
ps -eo pid,ppid,user,lstart,pcpu,pmem,args > "$D/ps.full"
ss -tulnp > "$D/ss_listen"; ss -tnp > "$D/ss_established"
ip a > "$D/ip.txt"; ip route > "$D/ip_route.txt"
cat /etc/resolv.conf > "$D/resolv.conf"
ls -la /proc/*/exe 2>/dev/null | grep deleted > "$D/deleted_exe"
lsmod > "$D/lsmod"; cat /proc/modules > "$D/proc_modules"
cat /etc/ld.so.preload > "$D/ld.so.preload"
ls /usr/local/lib/*.so > "$D/usr_local_lib.txt" 2>/dev/null
uptime > "$D/uptime"; date -Iseconds > "$D/date"

# --- Captura de proceso sospechoso (si se conoce PID) ---
# [requires:SUSPECT_PID]
P="{{SUSPECT_PID}}"
if [ -n "$P" ] && [ -d "/proc/$P" ]; then
  mkdir -p "$D/proc-$P"
  ls -la "/proc/$P/" > "$D/proc-$P/dir"
  for f in cmdline comm status environ maps; do
    cat "/proc/$P/$f" > "$D/proc-$P/$f" 2>/dev/null
  done
  readlink "/proc/$P/exe" > "$D/proc-$P/exe"
  ls -la "/proc/$P/fd/" > "$D/proc-$P/fd"
  cp "$(readlink /proc/$P/exe)" "$D/proc-$P/binary" 2>/dev/null
  sha256sum "$D/proc-$P/binary" > "$D/proc-$P/binary.sha256" 2>/dev/null
fi

# --- Archivos relevantes ---
cp -a /etc/crontab /etc/cron.d /var/spool/cron/crontabs \
  /etc/systemd/system /etc/ld.so.preload \
  /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh \
  "$D/" 2>/dev/null

# --- Logs ---
journalctl --since "{{SINCE}}" > "$D/journal.txt" 2>/dev/null
cp /var/log/auth.log /var/log/auth.log.1 "$D/" 2>/dev/null
last -F > "$D/last.log"; lastb -F > "$D/lastb.log"

# --- Hashing de integridad ---
  (
    cd "$D" || exit 1
    tmp=$(mktemp .evidence.sha256.XXXXXX) || exit 1
    if ! find . -type f ! -name 'evidence.sha256' ! -name '.evidence.sha256.*' -print0 \
        | sort -z \
        | xargs -0 -r sha256sum > "$tmp"; then
      rm -f -- "$tmp"
      exit 1
    fi
    mv -- "$tmp" evidence.sha256
  )
```

<!-- MODULE:helpers.hash_evidence -->

### Fase 2: Triage / categorizar (SOLO-LECTURA)
```bash
# [risk:ro] [mode:auto]
D="${OUTPUT_DIR:?}"
umask 077
# ¿Hay un miner?
grep -- "--coin=monero" "$D"/proc-*-cmdline 2>/dev/null && echo "[TRIAGE] Miner detectado"
# ¿Hay LD_PRELOAD rootkit?
grep -q kthreadd "$D/ld.so.preload" 2>/dev/null && echo "[TRIAGE] Rootkit LD_PRELOAD detectado"
# ¿Vectores de persistencia?
grep -E "kthreadd|Xorg\.X" "$D/crontab" "$D"/cron.d/* 2>/dev/null && echo "[TRIAGE] Persistencia en cron detectada"
```

### Fase 3: Containment — [risk:cont] [mode:confirm]
```bash
# [risk:cont] [mode:confirm]
# Bloqueo egress al C2 (no mata procesos, preserva evidencia)
read -r -a c2_ips <<< "${C2_IPS:-}"
for ip in "${c2_ips[@]}"; do
  python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$ip" || {
    echo "ERROR: C2_IPS contiene una dirección inválida" >&2; exit 2;
  }
  iptables -I OUTPUT -d "$ip" -j DROP
  echo "[CONTAINMENT] Bloqueada salida hacia $ip"
done

# Bloqueo de cuenta sólo tras validar identidad y alcance
if [ -n "${BACKDOOR_USER:-}" ]; then
  [[ "$BACKDOOR_USER" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*[$]?$ ]] || { echo "ERROR: BACKDOOR_USER inválido" >&2; exit 2; }
  getent passwd "$BACKDOOR_USER" >/dev/null || { echo "ERROR: usuario no existe" >&2; exit 2; }
  usermod -L "$BACKDOOR_USER"
  usermod -s /usr/sbin/nologin "$BACKDOOR_USER"
  gpasswd -d "$BACKDOOR_USER" sudo 2>/dev/null || true
  echo "[CONTAINMENT] Usuario bloqueado"
else
  echo "[SKIP] BACKDOOR_USER vacío; identificar y validar antes de contener"
fi

# Comentar entrada maliciosa en cron (con backup)
if [ -n "${CRON_BACKDOOR_FILE:-}" ]; then
  [[ "$CRON_BACKDOOR_FILE" == /* && -f "$CRON_BACKDOOR_FILE" && ! -L "$CRON_BACKDOOR_FILE" ]] || {
    echo "ERROR: CRON_BACKDOOR_FILE debe ser un archivo absoluto validado" >&2; exit 2;
  }
  echo "[REVIEW REQUIRED] Preservar y validar la entrada de cron antes de cambiarla"
else
  echo "[SKIP] CRON_BACKDOOR_FILE vacío; identificar y validar antes de contener"
fi
```

<!-- MODULE:helpers.block_c2_egress -->
<!-- MODULE:helpers.disable_backdoor_user -->

### Fase 4: Eradication — [risk:erad] [mode:confirm]
```bash
# [risk:erad] [mode:confirm]
D="{{OUTPUT_DIR}}"

# Eliminar binarios de malware
mapfile -t malware_paths <<< "${MALWARE_PATHS:-}"
for f in "${malware_paths[@]}"; do
  [ -n "$f" ] || continue
  [[ "$f" == /* && -f "$f" && ! -L "$f" ]] || { echo "ERROR: ruta de malware no válida" >&2; exit 2; }
  if [ -f "$f" ]; then
    sha256sum "$f" > "$D/erased_$(basename "$f").sha256" 2>/dev/null
    rm -f "$f"
    echo "[ERADICATION] Eliminado: $f"
  fi
done

# Limpiar ld.so.preload
cp /etc/ld.so.preload "$D/ld.so.preload.erased" 2>/dev/null
> /etc/ld.so.preload
echo "[ERADICATION] /etc/ld.so.preload limpiado"

# Eliminar usuario backdoor
if [ -n "${BACKDOOR_USER:-}" ]; then
  [[ "$BACKDOOR_USER" =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*[$]?$ ]] || { echo "ERROR: BACKDOOR_USER inválido" >&2; exit 2; }
  getent passwd "$BACKDOOR_USER" >/dev/null || { echo "ERROR: usuario no existe" >&2; exit 2; }
  userdel -r "$BACKDOOR_USER"
  echo "[ERADICATION] Usuario eliminado"
else
  echo "[SKIP] BACKDOOR_USER vacío; identificar y validar antes de erradicar"
fi

# Rotar SSH host keys
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' 2>/dev/null
echo "[ERADICATION] SSH host keys rotadas"

# Rotar root password
echo "[ERADICATION] Cambiar contraseña de root manualmente: passwd"

# Hardening inmediato de sshd
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config 2>/dev/null
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null
systemctl restart ssh 2>/dev/null
echo "[ERADICATION] sshd_config endurecido"
```

<!-- MODULE:helpers.remove_malware_binaries -->
<!-- MODULE:helpers.clean_ld_preload -->

### Fase 5: Recovery
- Rebuild host preferentemente desde una imagen nueva desplegada por IaC.
- Patch/upgrade all packages, disable unused services.
- Rotate application secrets tokens (DB, API keys).
- Restore data from verified clean backup.
- Monitor closely post-recovery (`journalctl -f`, auditd rules activas).

### Fase 6: Lessons Learned — Informe final
Checklist de cierre:
- [ ] forense preservado
- [ ] host contained
- [ ] malware removed
- [ ] persistence vectors stripped
- [ ] credentials rotated
- [ ] logs rotated to SIEM
- [ ] threat intel feed actualizado con nuevos IOCs
- [ ] nuevo hardening baseline aplicado

## Escalación a forense externo
Si el incidente es sofisticado, considerar:
- LiveCD / RedLine / Velociraptor offline.
- Imagen E01 con `dd` + `ewfacquire` / `FTK Imager for Linux`.
- Memory image con `LiME`, analizar con `volatility3`.
- Subir binarios a MalwareBazaar / VirusTotal.
- SSR con threat Intel (CrowdStrike, Mandiant).

## Falsos positivos
- Top CPU por `node /app/dist/main` (CI build normal).
- Brute force SSH desde bots != intrusión confirmada (solo ruido).
- chkrootkit LKM false positives (race condition de procesos efímeros).

## Buenas prácticas
- **Nunca reiniciar** durante la fase de colección: se pierde evidencia volátil.
- Siempre recolectar ANTES de contener, contener ANTES de erradicar.
- Documentar cada acción con timestamp y justificación.
- Mantener un canal Out-of-Band para comunicación durante el incidente.
- Hacer tabla de tiempos (timeline) correlacionando auth.log + last + wtmp + journalctl.

## Referencias
- NIST SP 800-61 R2: Computer Security Incident Handling Guide
- SANS PICERL Framework: https://www.sans.org/white-papers/34967/
- MITRE ATT&CK for Enterprise Linux
- Linux Forensics Quick Reference — SANS DFIR poster
- "Applied Incident Response" — Sammons
- "The Practice of Network Security Monitoring" — Richard Bejtlich
