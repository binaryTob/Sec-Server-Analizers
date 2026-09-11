# Server-Analizers

Repositorio de skills DFIR (Digital Forensics & Incident Response) para servidores Linux. Cada skill es un documento Markdown estructurado con frontmatter YAML, comandos bash parametrizables y tagging de riesgo, diseñado para ser consumido tanto por analistas humanos como por un orquestador de IA.

## Estructura

```
skills/
├── _schema.yaml          ← Contrato formal de cada skill (tipos, riesgo, output schema)
├── _index.yaml           ← Catálogo maestro + workflows predefinidos
├── _template.md          ← Plantilla canónica para crear nuevas skills
├── common/
│   └── helpers.md        ← 15 módulos reutilizables (collect, block, eradicate)
├── linux_forensics.md    ← Colección forense solo-lectura (RFC 3227)
├── cryptominer_detection.md ← Detección de XMRig/Kinsing/Sysrv/Rocke/Perfctl
├── malware_hunting.md    ← Caza de binarios y procesos maliciosos por firma
├── rootkit_detection.md  ← Detección de rootkits LKM y LD_PRELOAD userland
├── persistence_detection.md ← Enumeración de vectores T1547/T1053/T1136
├── log_analysis.md       ← Análisis de auth.log, syslog, journalctl, wtmp
├── ssh_forensics.md      ← Forense SSH: authorized_keys, sshd_config, auth
├── IOC_hunting.md        ← Caza de IOCs por categoría + generación de feeds
├── remote_readonly_triage.md ← Compromise Assessment remoto por SSH (solo-lectura, no escribe en el target)
├── incident_response.md  ← Orquestador PICERL end-to-end (contiene acciones write)
└── hardening.md          ← Auditoría CIS Benchmarks post-remediación
```

## Workflows predefinidos

| Workflow | Skills | Riesgo | Cuándo usarlo |
|----------|--------|--------|---------------|
| `quick_triage` | forensics + persistence + logs | solo-lectura | Sospecha inicial, 5 min |
| `compromise_assessment` | 8 skills de detección | solo-lectura | Assessment completo |
| `incident_response_full` | 10 skills + contención | contiene write | Incidente confirmado |
| `post_breach_hardening` | hardening | reconfiguración | Después de erradicar |
| `remote_compromise_assessment` | remote_readonly_triage | solo-lectura | Host remoto accesible solo por SSH, sin tocar el target |

## Cómo usarlo con IA

Cada skill está diseñada para ser parseable por un LLM/orquestador:

1. **Descubrimiento**: lee `skills/_index.yaml` para obtener el catálogo completo con dependencias y fases PICERL.
2. **Selección**: evalúa los `triggers` de cada skill contra los síntomas del host para determinar cuáles ejecutar.
3. **Parametrización**: sustituye las variables `{{OUTPUT_DIR}}`, `{{SUSPECT_PID}}`, `{{SINCE}}`, etc. con valores del contexto.
4. **Ejecución segura**: respeta los tags `[risk:ro]`, `[risk:cont]`, `[risk:erad]` y los modos `[mode:auto]` vs `[mode:confirm]` para no ejecutar comandos destructivos sin autorización.
5. **Composición**: respeta el grafo `depends_on`/`provides` del índice para ejecutar skills en el orden correcto.
6. **Reutilización**: inyecta helpers de `skills/common/helpers.md` cuando la skill referencia `<!-- MODULE:helpers.nombre -->`.

### Prompt ejemplo para iniciar una investigación

```
Analiza el host con IP X.X.X.X. Sospecha de cryptominer por CPU al 100%.
Usa el workflow compromise_assessment del repo Server-Analizers.
Parámetros: OUTPUT_DIR=/root/forensic-$(date +%Y%m%d), SINCE="3 days ago"
```

## Caso de Referencia

Varias skills incluyen IOCs y datos de un incidente real anonimizado, marcados explícitamente como **"Caso de Referencia"** en:
- Frontmatter YAML (`source: "Caso de Referencia"`)
- Cuerpo del documento (`**Caso de Referencia**`)

Estos datos sirven como training data para que la IA reconozca patrones reales de ataque (Perfctl/PerfX con XMRig + LD_PRELOAD rootkit), pero los valores concretos (IPs, wallets, hashes) son de un incidente específico y no constituyen un threat feed universal.

## Formato de skill

Cada skill sigue una estructura consistente con:

- **Frontmatter YAML**: id, categoría, fase PICERL, nivel de riesgo, parámetros tipados, dependencias, MITRE ATT&CK, IOCs con source
- **Pre-flight**: validación de entorno
- **Comandos**: bloques bash con tags `[risk:ro|cont|erad|reconf]` y `[mode:auto|confirm]`
- **Módulos**: `<!-- MODULE:helpers.nombre -->` para inyectar funciones reutilizables
- **Interpretación**: cómo leer los outputs
- **Falsos positivos**: qué descartar
- **Buenas prácticas**: recomendaciones post-análisis

Ver `skills/_schema.yaml` para el contrato completo y `skills/_template.md` para crear nuevas skills.
