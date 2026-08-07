---
id: "skill_id"
name: "Skill: Nombre descriptivo"
version: "2.0"
category: "detection"
phase: "ident"
risk: "readonly"
execution_mode: "auto"
depends_on: []
provides: []
triggers:
  - "Condición 1 que activa esta skill"
  - "Condición 2 que activa esta skill"
mitre_attack:
  - "TXXXX"
  - "TYYYY"
parameters:
  OUTPUT_DIR:
    type: "filepath"
    default: "/root/forensic-backup-$(date +%Y%m%d-%H%M%S)"
    description: "Directorio de salida para evidencia recolectada"
  TARGET_PID:
    type: "integer"
    required: false
    description: "PID del proceso sospechoso a analizar en detalle"
  SINCE:
    type: "datetime"
    default: "1 day ago"
    required: false
    description: "Ventana temporal de inicio para logs"
  UNTIL:
    type: "datetime"
    default: "now"
    required: false
    description: "Ventana temporal de fin para logs"
output:
  format: "json"
  schema: "output_schema"
---

# Skill: Nombre descriptivo

## Objetivo
Descripción concisa de lo que esta skill logra (1-2 frases).

## Cuándo usarla
- Trigger 1
- Trigger 2
- Trigger 3

## Parámetros

| Variable | Tipo | Requerido | Default | Descripción |
|----------|------|-----------|---------|-------------|
| `{{OUTPUT_DIR}}` | filepath | sí | auto-generado | Directorio donde se almacena la evidencia |
| `{{TARGET_PID}}` | integer | no | — | PID del proceso sospechoso |
| `{{SINCE}}` | datetime | no | `1 day ago` | Inicio de ventana temporal |

## Pre-flight (validación de entorno)
```bash
# [risk:info] [mode:auto]
mkdir -p "{{OUTPUT_DIR}}"
command -v ss >/dev/null 2>&1 || { echo "ERROR: ss no disponible"; exit 1; }
```

## Comandos

### 1. Contexto del sistema
```bash
# [risk:info] [mode:auto]
# Recolecta información básica del host
{
  echo "=== SYSTEM INFO ==="
  cat /etc/os-release
  uname -a
  uptime
  date
} | tee "{{OUTPUT_DIR}}/system_info.txt"
```

### 2. Análisis principal
```bash
# [risk:ro] [mode:auto]
# Descripción breve de lo que hace este bloque
ps -eo pid,ppid,user,lstart,pcpu,pmem,comm,args --sort=-pcpu | head -40 \
  | tee "{{OUTPUT_DIR}}/processes.txt"
```

### 3. Bloque con parámetro opcional
```bash
# [risk:ro] [mode:auto] [requires:TARGET_PID]
ls -la /proc/"{{TARGET_PID}}"/{cmdline,comm,exe,status,environ,maps,fd} \
  > "{{OUTPUT_DIR}}/proc-{{TARGET_PID}}.txt"
```

<!-- MODULE:helpers.collect_volatile -->
<!-- MODULE:helpers.hash_evidence -->

## Interpretación
- Hallazgo A → conclusión X
- Hallazgo B → conclusión Y

## Falsos positivos
- FP 1: descripción y cómo descartarlo
- FP 2: descripción y cómo descartarlo

## IOC conocidos
```yaml
iocs:
  - type: "ipv4-addr"
    value: "X.X.X.X"
    context: "C2 pool"
    confidence: "high"
  - type: "file:sha256"
    value: "abcdef..."
    context: "malware binary"
    confidence: "high"
```

## Buenas prácticas
- Recomendación 1
- Recomendación 2

## Referencias
- MITRE ATT&CK TXXXX - Nombre técnica
- URL / documento de referencia
