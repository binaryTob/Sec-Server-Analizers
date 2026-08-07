---
id: "cryptominer_detection"
name: "Skill: Cryptominer Detection en Linux"
version: "2.0"
category: "detection"
phase: "ident"
risk: "readonly"
execution_mode: "auto"
depends_on: ["linux_forensics"]
provides: ["incident_response", "malware_hunting", "rootkit_detection"]
triggers:
  - "CPU/swap altas inexplicables, uso continuo de núcleos (>80% sostenido)"
  - "Conexiones salientes a puertos stratum (3333/4444/5555/7777/9000/14433/14444)"
  - "Proceso llamado kthreadd (PID != 2), systemd-update, Xorg.X*, kdevtmpfsi"
  - "Reporte de ISP/Cloud de abuso de minería"
mitre_attack:
  - "T1496"   # Resource Hijacking
  - "T1571"   # Non-Standard Port
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio para almacenar evidencia recolectada"
  CPU_THRESHOLD:
    type: "float"
    default: 50.0
    required: false
    description: "Umbral de CPU (%) para considerar un proceso como sospechoso"
  STRATUM_PORTS:
    type: "string"
    default: "3333|4444|5555|7777|9000|14433|14444|8080|143|110"
    required: false
    description: "Regex de puertos a monitorear para tráfico stratum"
  SUSPECT_PID:
    type: "integer"
    required: false
    description: "PID específico de un proceso sospechoso para análisis profundo"
output:
  format: "json"
  schema: "output_schema"
iocs:
  - type: "x-mono-wallet"
    value: "4B7vsy8ccUwQufiyMN9jgoDphPUDzGUvBhE4f19U5z3WMPZqx2gjHrv2PxpuBSZRHAdD5qfEnPiApdFk4fhHZGVwU1YG1L2"
    context: "Wallet XMR del operador"
    confidence: "high"
  - type: "ipv4-addr"
    value: "89.117.109.224"
    context: "C2 pool XMRig puerto 143"
    confidence: "high"
  - type: "domain-name"
    value: "localhost0.xyz"
    context: "Dominio de entrega de dropper + payload"
    confidence: "high"
  - type: "email"
    value: "sarapena7979@gmail.com"
    context: "Email del operador en worker tag del pool"
    confidence: "medium"
---

# Skill: Cryptominer Detection en Linux

## Objetivo
Detectar cryptominers (XMRig, Kinsing, Sysrv, Rocke, 8220, Perfctl) residentes en un servidor Linux, identificar su pool/wallet, cadena de ejecución y mecanismo de persistencia asociado.

## Cuándo usarla
- CPU/swap altas inexplicables, uso continuo de núcleos.
- Conexiones salientes a puertos inusuales (3333/4444/5555/7777/9000) o a puertos comunes con payload stratum.
- Cualquier proceso llamado `kthreadd` (con PID != 2), `systemd-update`, `Xorg.X*`, `busybox` descargado, `kdevtmpfsi`.
- Reporte de ISP/Cloud de abuso de minería.

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio de salida para evidencia |
| `{{CPU_THRESHOLD}}` | float | no | 50.0 | Umbral de CPU % para filtrar procesos |
| `{{STRATUM_PORTS}}` | string | no | `3333\|4444\|...` | Regex de puertos stratum a monitorear |
| `{{SUSPECT_PID}}` | integer | no | — | PID sospechoso para análisis detallado |

## Pre-flight
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"
command -v ss >/dev/null 2>&1 || { echo "ERROR: ss no disponible"; exit 1; }
```

## Comandos

### 1. CPU por proceso
```bash
# [risk:ro] [mode:auto]
# Identifica procesos con mayor consumo de CPU
{
  echo "=== TOP $(date -Iseconds) ==="
  top -b -n1 -c | head -30
  echo "=== PS CPU SORT ==="
  ps -eo pid,user,pcpu,pmem,rss,comm,args --sort=-pcpu | head -20
  echo "=== KERNEL THREAD CHECK ==="
  ls -la /proc/2/exe 2>/dev/null
} | tee "{{OUTPUT_DIR}}/cpu_processes.txt"
```

### 2. Conexiones salientes
```bash
# [risk:ro] [mode:auto]
# Busca conexiones establecidas hacia puertos de pool de minería
{
  echo "=== ALL ESTABLISHED DESTINATIONS ==="
  ss -tnp state established | awk '{print $5}' | sort -u
  echo "=== STRATUM PORTS ==="
  ss -tnp | grep -E ":{{STRATUM_PORTS}}"
} | tee "{{OUTPUT_DIR}}/network_stratum.txt"
```

### 3. Cmdline de todos los procesos (detección de minería)
```bash
# [risk:ro] [mode:auto]
# Escanea /proc en busca de argumentos de minería conocidos
{
  echo "=== MINING CMDLINE SCAN ==="
  for p in /proc/[0-9]*; do
    tr '\0' ' ' < "$p/cmdline" 2>/dev/null | \
      grep -E "stratum|xmrig|--coin=monero|--cpu-priority|--donate-level|cryptonight|=.*x|wallet" \
      && echo "  -> $p"
  done
} | tee "{{OUTPUT_DIR}}/mining_cmdline.txt"
```

### 4. Búsqueda de binarios de miner conocidos
```bash
# [risk:ro] [mode:auto]
# Rastrea el filesystem en busca de binarios con nombres de miner
{
  echo "=== MINING BINARIES FOUND ==="
  find / -xdev -type f \( \
    -name 'kthreadd*' -o -name 'Xorg.X*' -o -name 'xmrig*' \
    -o -name 'kdevtmpfsi' -o -name 'cnrig*' -o -name 'minerd*' \
    -o -name 'systemd-update' \) 2>/dev/null
} | tee "{{OUTPUT_DIR}}/mining_binaries.txt"

# Hashear los encontrados
sha256sum $(find / -xdev -type f \( -name 'kthreadd*' -o -name '*xmrig*' \) 2>/dev/null) 2>/dev/null \
  > "{{OUTPUT_DIR}}/mining_binaries.sha256"
```

### 5. Análisis de strings en binarios sospechosos
```bash
# [risk:ro] [mode:auto] [requires:SUSPECT_BINARIES]
# Extrae strings de los binarios para identificar pools, wallets, configuraciones
for bin in {{SUSPECT_BINARIES}}; do
  echo "=== STRINGS: $bin ==="
  strings -n 8 "$bin" 2>/dev/null | grep -iE \
    "pool|xmrig|monero|stratum|wallet|donate|--cpu|143|3333|4444"
done | tee "{{OUTPUT_DIR}}/strings_analysis.txt"
```

### 6. Persistencia asociada al miner
```bash
# [risk:ro] [mode:auto]
# Busca referencias al miner en vectores de persistencia
grep -rEi "kthreadd|Xorg\.X|xmr|stratum|donate-level" \
  /etc/cron* /etc/systemd/system /var/spool/cron \
  /etc/rc.local /etc/profile /etc/profile.d /root/.bashrc 2>/dev/null \
  | tee "{{OUTPUT_DIR}}/mining_persistence.txt"

cat /etc/ld.so.preload > "{{OUTPUT_DIR}}/ld.so.preload"
systemctl list-timers --all > "{{OUTPUT_DIR}}/systemd_timers.txt"
ls -la /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* > "{{OUTPUT_DIR}}/cron_listing.txt" 2>/dev/null
```

<!-- MODULE:helpers.collect_process_detail -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- Cmdline `kthreadd64 ... --cpu-priority=N --donate-level=0 -o <ip>:<port> -u <wallet[.worker/email]> --coin=monero -k` → **XMRig** minando Monero.
- Wallet Monero (XMR): base58 de ~95 caracteres, empieza con `4` o `8`.
- Pool addresses típicas: `pool.supportxmr.com:3333`, `pool.minexmr.com:4444`, `gulf.moneroocean.stream:10128`, IPs en `89.117.*.*`, `138.2.*.*`.
- `--donate-level=0` → el atacante removió la donación al dev de XMRig (rasgo típico de miner malicioso).
- `-k` → keepalive para reconexión automática al pool.
- LD_PRELOAD rootkit que hookea `readdir` para ocultar el proceso del miner.

## Falsos positivos
- `kthreadd` PID 2 del kernel (`/proc/2/exe -> (deleted)`): proceso legítimo del kernel.
- `node_exporter`, `newrelic-infra`: agentes de observabilidad legítimos (~20 MB Go binary).
- Herramientas de benchmarking: `stress-ng`, `BOINC` → raro en servidores de producción.

## Buenas prácticas
- Si el miner vive en un container Docker: aislar el host antes de interactuar con el container.
- Verificar tráfico por container: `docker stats --no-stream` y `iptables -L DOCKER-USER -n -v`.
- Comparar hash del binario contra MalwareBazaar/HybridAnalysis antes de eliminar.
- Bloquear dominio C2 e IP del pool en firewall egress inmediatamente después de la colección forense.
- Verificar regresión de LD_PRELOAD: si se limpia `ld.so.preload` y el proceso sigue oculto → LKM rootkit.

## Referencias
- MITRE ATT&CK: T1496 (Resource Hijacking), T1571 (Non-Standard Port)
- TrendMicro: "Detecting and Mitigating Cryptomining Malware in Linux"
- CrowdStrike: "8220 Gang"; Aqua: "perfctl" (14/08/2024)
- MalwareBazaar: https://bazaar.abuse.ch/
- `localhost0.xyz` asociado a campaña Perfctl/PerfX
- Tinymanw Dhilip: "ld.so.preload malware family"
