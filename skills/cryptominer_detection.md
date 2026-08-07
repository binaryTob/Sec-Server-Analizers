# Skill: Cryptominer Detection en Linux

## Objetivo
Detectar cryptominers (XMRig/Kinsing/Sysrv/Rocke/8220/etc.) residentes en un servidor Linux, identificar su pool/wallet, su cadena de ejecución y su mecanismo de persistencia.

## Cuándo usarla
- CPU/swap altas inexplicables, uso continuo de núcleos.
- Conexiones salientes a puertos inusuales (3333/4444/5555/7777/9000) o a puertos comunes con payload de stratum.
- Cualquier proceso llamado `kthreadd`, `systemd-update`, `Xorg.X*`, `busybox` descargado, `kdevtmpfsi`.
- Reporte de ISP/Cloud de abuso de minería.

## Comandos
```bash
# 1. CPU por proceso --------------------------------
top -b -n1 -c | head -30
ps -eo pid,user,pcpu,pmem,rss,comm,args --sort=-pcpu | head -20
# kernel 5.x+: verificar que el que dice "kthreadd" sea PID 2 (no un binario/file)
ls -la /proc/2/exe   # debe ser /proc/2/exe -> (deleted)=kernel

# 2. Conexiones salientes ---------------------------
ss -tnp state established | awk '{print $5}'
ss -tnp | grep -E ':3333|:4444|:5555|:7777|:9000|:14444|:14433|:8080|:143|:110'
# 3. Cmdline de todos los procesos -----------------
for p in /proc/[0-9]*; do tr '\0' ' ' < "$p/cmdline" 2>/dev/null |
  grep -E "stratum|xmrig|--coin=monero|--cpu-priority|--donate-level|cryptonight|=.*x|wallet" && echo "  -> $p"; done

# 4. Buscar/binarios de miner conocidos ------------
find / -xdev -type f \( -name 'kthreadd*' -o -name 'Xorg.X*' -o -name 'xmrig*' \
  -o -name 'kdevtmpfsi' -o -name 'cnrig*' -o -name 'minerd*' -o -name 'systemd-update' \) 2>/dev/null
sha256sum $(find / -xdev -type f \( -name 'kthreadd*' -o -name '*xmrig*' \) 2>/dev/null) 2>/dev/null

# 5. Strings ----------------------------------------
strings -n 8 /example/synthetic-miner /example/synthetic-dropper /example/synthetic-library.so 2>/dev/null \
  | grep -iE "pool|xmrig|monero|stratum|wallet|donate|\-\-cpu|143|3333|4444"

# 6. Persistencia -----------------------------------
grep -rEi "kthreadd|Xorg\.X|xmr|stratum|donate-level" /etc/cron* /etc/systemd/system /var/spool/cron /etc/rc.local /etc/profile /etc/profile.d /root/.bashrc 2>/dev/null
cat /etc/ld.so.preload

# 7. Cron + systemd timers --------------------------
systemctl list-timers --all; ls -la /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/*
```

## Interpretación
- Cmdline `kthreadd64 ... --cpu-priority=N --donate-level=0 -o <ip>:<port> -u <wallet[.worker/email]> --coin=monero -k`
  → es **XMRig** (clon o parchado) minando Monero.
- Wallet Monero (XMR): base58 ~95 chars, empieza con `4` o `8`.
- Pool address usual: `pool.supportxmr.com:3333`, `pool.minexmr.com:4444`, `gulf.moneroocean.stream:10128`, IPs en 198.51.*.*, 138.2.*.*
- `--donate-level=0` → el atacante removió la donación al dev de XMRig (rasgo típico).
- `-k` → keepalive, reconexión.
- LD_PRELOAD rootkit `synthetic-library.so` que hooke `readdir` para ocultar el proceso `kthreadd64`.

## IOC conocidos
- Wallet (caso típico): `SYNTHETIC_WALLET_EXAMPLE`
- Worker pattern `worker55/synthetic@example.invalid` → email del operador.
- Pool C2: `203.0.113.99:143`
- Domain delivery: `example.invalid` (entrega dropper + inf.txt).
- Archivos delivery: `Xorg.X13`, `busybox.static`, `core.tar.gz`, `systemd-update` (renamed `kthreadd64`), `synthetic-library.so`.

## Falsos positivos
- `kthreadd` PID 2 del kernel (`/proc/2/exe -> /proc/2/exe (deleted)` por el kernel no mapeado).
- `systemd-update` real de RAM de actualización del sistema: pero el servicio no debe vivir fuera de /usr/lib/systemd no spawn procesos que ahora ejecutan cmd con creds/monero.
- Herramientas de benchmarking como stress-ng, BOINC → raro en servidor.

## Buenas prácticas
- Si el minero vive dentro de un container de Docker: aislar host primero (detach del container en investigaciones live malware).
- Tasas de network por container: `docker stats --no-stream` y `iptables -L DOCKER-USER -n -v`.
- Compare hash del binario sospechoso contra MalwareBazaar - si está reportado sube a nueva convergencia (IP/wallet/email) del grupo.
- Blockear el dominio C2 y la IP del pool en firewall egress inmediatamente luego de la colección.
- Reúse `LD_PRELOAD` regression check online plataformas para verificar el rootkit (Libprocesshider github de jordan-ja).

## Referencias
- MITRE ATT&CK T1496 - Resource Hijacking.
- TrendMicro "Detecting and Mitigating Cryptomining Malware in Linux".
- CrowdStrike "8220 Gang", Aqua "perfctl" (14082024).
- http://example.invalid descritos: el miner "perfctl/sys UpdateMimic" o variante.
- Tinymanw Dhilip "ld.so.preload malware family".
- Mitigation: egress firewall allow-list.