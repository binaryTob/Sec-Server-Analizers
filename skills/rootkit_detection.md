---
id: "rootkit_detection"
name: "Skill: Rootkit Detection en Linux"
version: "2.0"
category: "detection"
phase: "ident"
risk: "readonly"
execution_mode: "auto"
depends_on: ["cryptominer_detection", "malware_hunting"]
provides: ["incident_response", "persistence_detection"]
triggers:
  - "Procesos que no aparecen en ps pero sí en /proc (discrepancia de conteo)"
  - "/proc/<pid>/exe apunta a (deleted) o a ruta inexistente"
  - "chkrootkit/rkhunter reportan 'process hidden' o 'Possible LKM Trojan'"
  - "Compromise Assessment de rutina"
mitre_attack:
  - "T1014"      # Rootkit (LKM)
  - "T1547.007"  # ld.so.preload
  - "T1574.006"  # Dynamic Linker Hijacking
  - "T1562.001"  # Disable or Modify Tools
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar evidencia"
  SCAN_TOOLS:
    type: "string"
    default: "chkrootkit,rkhunter,unhide"
    required: false
    description: "Herramientas de escaneo a ejecutar (separadas por coma)"
  SUSPECT_SO_PATH:
    type: "filepath"
    default: "/usr/local/lib/kthreadd32.so"
    required: false
    description: "Ruta de la librería .so sospechosa para análisis de strings"
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "filepath"
    value: "/usr/local/lib/kthreadd32.so"
    context: "LD_PRELOAD rootkit — oculta procesos del miner"
    source: "Caso de Referencia"
    confidence: "high"
  - type: "filepath"
    value: "/etc/ld.so.preload"
    context: "Vector de carga del rootkit userland"
    source: "Caso de Referencia"
    confidence: "high"
  - type: "filename"
    value: "libprocesshider.so"
    context: "PoC didáctico de GitHub abusado por atacantes"
    source: "comunidad"
    confidence: "medium"
---

# Skill: Rootkit Detection en Linux

## Objetivo
Detectar rootkits de usuario (userland, LD_PRELOAD T1547.007), rootkits de kernel (LKM T1014) y técnicas de ocultación de procesos/archivos en un host Linux comprometido, diferenciando falsos positivos de infecciones reales.

## Cuándo usarla
- Procesos que no aparecen en `ps` pero sí en `/proc`.
- `/proc/<pid>/exe` apunta a `(deleted)` o a ruta inexistente.
- chkrootkit/rkhunter reportan "process hidden" o "Possible LKM Trojan".
- En todo Compromise Assessment como rutina.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de salida |
| `{{SCAN_TOOLS}}` | string | no | `chkrootkit,rkhunter,unhide` | Herramientas a ejecutar |
| `{{SUSPECT_SO_PATH}}` | filepath | no | `/usr/local/lib/kthreadd32.so` | .so sospechosa a analizar |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"
```

## Comandos

### 1. Detección de LKM rootkits (T1014)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== LOADED KERNEL MODULES ==="
  lsmod
  echo "=== KERNEL SYMBOLS (first 30) ==="
  cat /proc/kallsyms 2>/dev/null | awk '$3=="t" || $3=="T"' | head -30
  echo "=== MODULE SIGNATURE CHECK ==="
  for m in $(awk '{print $1}' /proc/modules); do
    sig=$(modinfo "$m" 2>/dev/null | grep -i signer)
    echo "$m : ${sig:-NO-SIGNER}"
  done
  echo "=== MODULE DETAILS ==="
  cat /proc/modules
} | tee "{{OUTPUT_DIR}}/lkm_detection.txt"
```

### 2. Detección de LD_PRELOAD userland (T1547.007)
```bash
# [risk:ro] [mode:auto]
{
  echo "=== LD.SO.PRELOAD ==="
  cat /etc/ld.so.preload 2>/dev/null
  echo "=== LD CONFIG ==="
  cat /etc/ld.so.conf 2>/dev/null
  ls -la /etc/ld.so.conf.d/ 2>/dev/null
  echo "=== EXTRA LIBRARIES ==="
  ls -la /usr/local/lib/*.so /lib/x86_64-linux-gnu/*.so 2>/dev/null
} | tee "{{OUTPUT_DIR}}/ld_preload_check.txt"

# Verificar preload activo en procesos vivos
{
  echo "=== ACTIVE LD_PRELOAD IN PROCESSES ==="
  for p in /proc/[0-9]*/environ; do
    if grep -q LD_PRELOAD "$p" 2>/dev/null; then
      echo "$p"
      tr '\0' '\n' < "$p" 2>/dev/null | grep LD_PRELOAD
    fi
  done
} | tee "{{OUTPUT_DIR}}/active_preload.txt"

# Análisis de hooks en librería sospechosa
{
  echo "=== HOOK ANALYSIS: {{SUSPECT_SO_PATH}} ==="
  file "{{SUSPECT_SO_PATH}}" 2>/dev/null
  sha256sum "{{SUSPECT_SO_PATH}}" 2>/dev/null
  strings -a "{{SUSPECT_SO_PATH}}" 2>/dev/null | grep -Ei \
    "readdir|opendir|__lxstat|lstat|readlink|closedir|unlink|processhider|hide|proc"
} | tee "{{OUTPUT_DIR}}/so_hook_analysis.txt"
```

### 3. Detección de procesos ocultos
```bash
# [risk:ro] [mode:auto]
{
  echo "=== HIDDEN PROCESS DETECTION ==="
  ps_count=$(ps -e --no-headers | wc -l)
  proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
  echo "ps_count=$ps_count  proc_count=$proc_count  diff=$((proc_count - ps_count))"
  if [ "$ps_count" -ne "$proc_count" ]; then
    echo "WARNING: ps != /proc — posible rootkit"
    echo "=== DIFF ==="
    diff <(ls /proc | grep -E '^[0-9]+$' | sort -n) \
         <(ps -e --no-headers | awk '{print $1}' | sort -n) 2>/dev/null
  fi
  echo "=== DELETED-BUT-OPEN BINARIES ==="
  ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
} | tee "{{OUTPUT_DIR}}/hidden_processes.txt"

# Procesos ejecutándose desde ubicaciones anómalas
{
  echo "=== PROCESSES FROM SUSPICIOUS LOCATIONS ==="
  for p in /proc/[0-9]*; do
    link=$(readlink "$p/exe" 2>/dev/null)
    case "$link" in
      *deleted*|"") ;;
      /tmp/*|/dev/shm/*|/var/tmp/*)
        echo "PID ${p#/proc/}: $link"
        ;;
    esac
  done
} | tee "{{OUTPUT_DIR}}/suspicious_locations.txt"
```

### 4. Verificación de integridad de binarios del sistema
```bash
# [risk:ro] [mode:auto]
{
  echo "=== DPKG VERIFY (modified files) ==="
  dpkg --verify 2>/dev/null | grep -E "ps$|ls$|ss$|top$|netstat$|ifconfig$"
  echo "=== DEBSUMS CHECK ==="
  debsums -c 2>/dev/null | grep -E "/(ps|ls|top|ss|netstat)$"
} | tee "{{OUTPUT_DIR}}/binary_integrity.txt"
```

### 5. rkhunter (scanner recomendado)
```bash
# [risk:ro] [mode:auto] [requires:rkhunter]
rkhunter --update 2>/dev/null
rkhunter --check --skip-keypress --report-warnings-only \
  > "{{OUTPUT_DIR}}/rkhunter_scan.txt" 2>&1
```

### 6. chkrootkit
```bash
# [risk:ro] [mode:auto] [requires:chkrootkit]
{
  chkrootkit 2>/dev/null
  echo "=== HIDDEN PROCESSES (chkproc) ==="
  chkproc 2>/dev/null
  echo "=== HIDDEN DIRECTORIES (chkdirs) ==="
  chkdirs 2>/dev/null
} | tee "{{OUTPUT_DIR}}/chkrootkit_scan.txt"
```

### 7. Herramientas auxiliares
```bash
# [risk:ro] [mode:auto]
{
  for tool in unhide tiger checksec aide osqueryi lynis; do
    path=$(which "$tool" 2>/dev/null)
    echo "$tool: ${path:-NOT FOUND}"
  done
} | tee "{{OUTPUT_DIR}}/tools_available.txt"

# unhide: hunting de procesos ocultos
which unhide >/dev/null 2>&1 && unhide-linux brute \
  > "{{OUTPUT_DIR}}/unhide_scan.txt" 2>&1
```

<!-- MODULE:helpers.collect_volatile -->
<!-- MODULE:helpers.collect_process_detail -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- `/etc/ld.so.preload` debe estar vacío o no existir. Si tiene entrada → **rootkit userland**: la librería hookea glibc para esconder archivos/procesos (típica `libprocesshider.so`, `kthreadd32.so`).
- Hooks típicos: `readdir`, `readdir64`, `opendir`, `lstat`, `__xstat`, `readlink`, `unlink`, `filefilldir`.
- Hidden processes (`ps != /proc`) → LKM rootkit o race condition (FP común).
- chkrootkit "Possible LKM Trojan" + "N process hidden" → race condition con procesos efímeros (cron, ps mismo, forks sshd). Re-validar en idle.
- ifpromisc sobre `systemd-networkd` → **FP**: es el daemon legítimo de networking.
- `dpkg --verify` marcando `??5??????` sobre `/bin/ps` o `/usr/bin/top` → binario reemplazado por rootkit.
- Módulos de kernel sin signer en sistemas con Secure Boot → sospechoso.

## IOC de rootkits conocidos
- `libprocesshider.so` (GitHub: jordan-ja, PoC didáctico abusado).
- `kthreadd32.so`, `kthreadd.so`, `libs.so`, `libsys.so` en `/usr/local/lib` o `/lib`.
- `kdevtmpfsi` con `/proc/2/exe` modificado.
- Módulos en `/proc/modules` con LICENSE no estándar o sin signer.
- Binarios en `/bin` reemplazados (`nulled`) con permisos extraños.
- **Caso de Referencia**: `/usr/local/lib/kthreadd32.so`, compilada in-situ con `gcc -Wall -fPIC -shared -o kthreadd32.so kthreadd32.c -ldl`, instalada vía `ld.so.preload`.

## Falsos positivos
- chkrootkit "process hidden for readdir" con alta carga → race condition con procesos efímeros. Re-correr en idle.
- rkhunter FP en módulos: "Possibly hardened kernel".
- `systemd-networkd` marcado como PACKET SNIFFER → legítimo.
- `dpkg --verify` en conffiles modificados por admin: FP frecuente.
- Binarios `(deleted)` en `/proc/*/exe` con PID de corta vida (cron jobs) → no son malware.

## Buenas prácticas
- Restringir carga de módulos kernel: `/etc/modprobe.d` con allowlist + Secure Boot (dm-verity).
- Mantener `ps`, `ls`, `top`, `netstat`, `ss` originales y verificados con `debsums -c`.
- File Integrity Monitoring con AIDE: `apt install aide && aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db`.
- MAC enforcing: AppArmor profiles estrictos para `/usr/local/lib`.
- Reglas auditd para monitorizar `ld.so.preload`:
  ```
  auditctl -w /etc/ld.so.preload -p wa -k preload_watch
  auditctl -w /usr/local/lib -p wa -k lib_watch
  auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k modules
  ```
- Reinstalar paquetes sospechosos: `apt install --reinstall coreutils procps net-tools`.

## Referencias
- MITRE ATT&CK: T1014, T1547.007, T1574.006, T1562.001
- chkrootkit: https://github.com/Magentron/chkrootkit
- rkhunter: https://rkhunter.sourceforge.net/
- libprocesshider PoC: https://github.com/jordan-ja/libprocesshider
- Linux Kernel Runtime Guard (LKRG): https://lkrg.org
- `man 8 ld.so` — definición de `/etc/ld.so.preload`, `rpath`
