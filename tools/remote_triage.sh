#!/usr/bin/env bash
# ============================================================
# remote_triage.sh — Reusable runner for the `remote_readonly_triage` skill.
#
# Executes a read-only Compromise Assessment against a Linux host over SSH,
# capturing all evidence LOCALLY (RFC 3227). It NEVER writes to the target:
# every block is executed on the remote via `bash -s` reading from stdin.
#
# Nothing is hardcoded: host, port, user, ssh args, output dir and timeouts
# are CLI parameters. Authentication relies on your existing SSH setup (key
# in the agent or BatchMode). See `--help`.
#
# Robustness: every step is bounded by `--step-timeout`. If a step is slow
# (e.g. `find /` on a big filesystem) it is cut off after that many seconds
# but the collection KEEPS GOING — the partial output is preserved locally
# and the remaining steps still run. A single slow command never aborts the
# whole assessment.
#
# Usage:
#   ./tools/remote_triage.sh --host 198.51.100.27 --port 22 --user root \
#       --output-dir ./forensic-remote-$(date +%Y%m%d-%H%M%S) --since "30 days ago"
#
# ============================================================
set -u

usage() {
  cat <<'EOF'
Usage: remote_triage.sh --host HOST [options]

Run the remote_readonly_triage skill (read-only Compromise Assessment) over SSH.

Required:
  --host HOST          IP or hostname of the remote server
Options:
  --port PORT          SSH port (default: 22)
  --user USER          SSH user (default: root)
  --ssh-args ARGS      Extra ssh args, e.g. '-i ~/.ssh/id_ed25519' (default: "")
  --output-dir DIR     LOCAL evidence directory (default: ./forensic-remote-<ts>)
  --since WHEN         journalctl --since window (default: "1 day ago")
  --step-timeout SECS  Max seconds per remote step before cutting it off and
                       moving on (default: 120). 0 disables the timeout.
  --help               Show this help

Example:
  ./tools/remote_triage.sh --host server.example.net --port 22 --user analyst \
      --output-dir ./forensic-remote-$(date +%Y%m%d-%H%M%S) --since "30 days ago"
EOF
}

HOST=""
PORT="22"
USER="root"
SSH_ARGS=""
OUTPUT_DIR=""
SINCE="1 day ago"
STEP_TIMEOUT="120"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) USER="$2"; shift 2 ;;
    --ssh-args) SSH_ARGS="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --since) SINCE="$2"; shift 2 ;;
    --step-timeout) STEP_TIMEOUT="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option '$1'"; usage; exit 1 ;;
  esac
done

if [ -z "$HOST" ]; then
  echo "ERROR: --host is required"
  usage
  exit 1
fi

command -v ssh >/dev/null 2>&1 || { echo "ERROR: ssh not available locally"; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo "ERROR: 'timeout' (coreutils) not available locally"; exit 1; }

OUTPUT_DIR="${OUTPUT_DIR:-./forensic-remote-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new ${SSH_ARGS}"
remote() {
  ssh ${SSH_OPTS} -p "${PORT}" "${USER}@${HOST}" bash -s
}

# run_remote OUTPUTFILE
# Reads the read-only script from stdin and runs it on the remote host via
# `bash -s`. Captures stdout+stderr into OUTPUTFILE locally. Bounded by
# STEP_TIMEOUT; on timeout/failure it warns and continues so the assessment
# never dies on a single slow command.
run_remote() {
  local out="$1"
  if [ "${STEP_TIMEOUT}" != "0" ]; then
    if timeout "${STEP_TIMEOUT}" remote > "$out" 2>&1; then
      return 0
    fi
    echo "    [!] step cut off after ${STEP_TIMEOUT}s — partial data kept in ${out} (continuing)"
    return 1
  fi
  remote > "$out" 2>&1
}

echo "[*] Host: ${USER}@${HOST}:${PORT}"
echo "[*] Evidence dir (local): ${OUTPUT_DIR}"
echo "[*] Log window: ${SINCE}"
echo "[*] Per-step timeout: ${STEP_TIMEOUT}s"

# --- 0. Connectivity (readonly). Aborts cleanly on failure. ---
echo "[*] (0/12) Connectivity test ..."
timeout 30 remote > "$OUTPUT_DIR/00_connectivity.txt" 2>&1 <<'EOF'
echo "=== CONNECTIVITY $(date -Iseconds) ==="
hostname
uname -a
id
date -Iseconds
uptime
EOF
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ERROR: could not connect to ${USER}@${HOST}:${PORT}"
  cat "$OUTPUT_DIR/00_connectivity.txt"
  exit 1
fi
cat "$OUTPUT_DIR/00_connectivity.txt"

# --- 1. System context ---
echo "[*] (1/12) System context ..."
run_remote "$OUTPUT_DIR/01_system_context.txt" <<'EOF'
echo "=== OS ==="; head -5 /etc/os-release
echo "=== UPTIME ==="; uptime
echo "=== DATE ==="; date -Iseconds
echo "=== LAST REBOOT ==="; last reboot | head -5
echo "=== CPU ==="; lscpu | head -12
echo "=== MEM ==="; free -h
echo "=== DISK ==="; df -h
echo "=== LOAD ==="; cat /proc/loadavg
EOF

# --- 2. Processes and memory (volatile) ---
echo "[*] (2/12) Processes ..."
run_remote "$OUTPUT_DIR/02_processes.txt" <<'EOF'
echo "=== TOP CPU ==="; ps -eo pid,ppid,user,lstart,etime,pcpu,pmem,comm,args --sort=-pcpu | head -40
echo "=== TOP RSS ==="; ps -eo pid,ppid,user,pmem,rss,args --sort=-rss | head -25
echo "=== PS vs /proc COUNT ==="; echo "ps=$(ps -e --no-headers | wc -l) proc=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
echo "=== FROM /tmp /dev/shm /var/tmp ==="; ps -eo pid,user,args | grep -E "/tmp|/dev/shm|/var/tmp" | grep -v grep
echo "=== DELETED-BUT-OPEN EXE ==="; ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
EOF

# --- 3. Network ---
echo "[*] (3/12) Network state ..."
run_remote "$OUTPUT_DIR/network_state.txt" <<'EOF'
echo "=== LISTENERS ==="; ss -tulnp
echo "=== ESTABLISHED ==="; ss -tnp state established
echo "=== UNCOMMON LISTENERS ==="; ss -tulnp | grep -vE ':(22|80|443) '
echo "=== INTERFACES ==="; ip -br a
echo "=== ROUTES ==="; ip route show
echo "=== FIREWALL (nft) ==="; nft list ruleset 2>/dev/null | head -60
echo "=== FIREWALL (iptables) ==="; iptables -L -n -v 2>/dev/null
EOF

# --- 4. Persistence: cron ---
echo "[*] (4/12) Cron ..."
run_remote "$OUTPUT_DIR/03_cron.txt" <<'EOF'
echo "=== /etc/crontab ==="; cat /etc/crontab 2>/dev/null
echo "=== /etc/cron.d ==="; for f in /etc/cron.d/*; do [ -f "$f" ] && echo "### $f" && cat "$f"; done
echo "=== cron dirs ==="; ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
echo "=== spool ==="; ls -laR /var/spool/cron/ 2>/dev/null
echo "=== root crontab ==="; crontab -l 2>/dev/null
EOF

# --- 5. Persistence: systemd + timers ---
echo "[*] (5/12) systemd ..."
run_remote "$OUTPUT_DIR/04_systemd.txt" <<'EOF'
echo "=== ENABLED UNITS ==="; systemctl list-unit-files --state=enabled 2>/dev/null
echo "=== RUNNING SERVICES ==="; systemctl list-units --type=service --state=running --no-pager 2>/dev/null
echo "=== FAILED SERVICES ==="; systemctl list-units --type=service --state=failed --no-pager 2>/dev/null
echo "=== TIMERS ==="; systemctl list-timers --all --no-pager 2>/dev/null
echo "=== /etc/systemd/system tree ==="; ls -laR /etc/systemd/system/ 2>/dev/null | head -150
EOF

# --- 6. Persistence: rc, shell rc, ld.so.preload, modules ---
echo "[*] (6/12) Autostart ..."
run_remote "$OUTPUT_DIR/05_autostart.txt" <<'EOF'
echo "=== /etc/ld.so.preload ==="; cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/ld.so.preload 2>/dev/null
echo "=== /etc/ld.so.conf.d ==="; cat /etc/ld.so.conf.d/*.conf 2>/dev/null
echo "=== custom .so in /usr/local/lib ==="; ls -la /usr/local/lib/*.so* 2>/dev/null
echo "=== /etc/rc.local ==="; cat /etc/rc.local 2>/dev/null
echo "=== ~/.bashrc (tail) ==="; tail -40 ~/.bashrc 2>/dev/null
echo "=== ~/.profile ==="; cat ~/.profile 2>/dev/null
echo "=== /etc/profile.d ==="; ls -la /etc/profile.d/ 2>/dev/null
echo "=== /etc/environment ==="; cat /etc/environment 2>/dev/null
echo "=== modules-load.d ==="; ls -la /etc/modules-load.d/ 2>/dev/null; cat /etc/modules-load.d/* 2>/dev/null
EOF

# --- 7. Users and accounts ---
echo "[*] (7/12) Users ..."
run_remote "$OUTPUT_DIR/06_users.txt" <<'EOF'
echo "=== UID 0 users ==="; grep -E ':x:0:' /etc/passwd
echo "=== users with shell ==="; grep -E '/(bash|sh)$' /etc/passwd
echo "=== non-system users (uid>=1000) ==="; awk -F: '$3>=1000 && $3<65534 {print}' /etc/passwd
echo "=== passwords set (shadow) ==="; awk -F: '($2!="*" && $2!="!" && $2!="!!" && $2!="") {print $1":HASH_SET"}' /etc/shadow 2>/dev/null
echo "=== sudo group ==="; getent group sudo admin wheel 2>/dev/null
echo "=== sudoers NOPASSWD ==="; grep -rE 'NOPASSWD|ALL=\(ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
echo "=== useradd/usermod in logs ==="; grep -hE 'useradd|usermod|chpasswd' /var/log/auth.log* 2>/dev/null | tail -30
EOF

# --- 8. SSH ---
echo "[*] (8/12) SSH ..."
run_remote "$OUTPUT_DIR/07_ssh.txt" <<'EOF'
echo "=== my .ssh ==="; ls -la ~/.ssh/ 2>/dev/null
echo "=== authorized_keys (with comments) ==="; grep -vE '^#|^$' ~/.ssh/authorized_keys 2>/dev/null | awk '{print $1, $3}'
echo "=== fingerprints ==="; ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null
echo "=== authorized_keys backups ==="; ls -la ~/.ssh/authorized_keys* 2>/dev/null
echo "=== sshd_config (active) ==="; grep -vE '^\s*#|^\s*$' /etc/ssh/sshd_config 2>/dev/null
echo "=== sshd_config.d ==="; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null
echo "=== effective sshd -T (key params) ==="; sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|usepam|allowusers|allowgroups|authorizedkeysfile|permitemptypasswords|x11forwarding|allowtcpforwarding|permittunnel|trustedusercakeys|authorizedprincipalsfile)'
EOF

# --- 9. Auth logs ---
echo "[*] (9/12) Auth logs ..."
run_remote "$OUTPUT_DIR/08_auth.txt" <<EOF
echo "=== AUTH FILES ==="; ls -la /var/log/auth.log* 2>/dev/null
echo "=== ACCEPTED LOGINS ==="; grep -hE 'Accepted' /var/log/auth.log /var/log/auth.log.1 2>/dev/null | tail -60
echo "=== SOURCE IPs (freq) ==="; grep -hE 'Accepted (publickey|password|keyboard-interactive)' /var/log/auth.log* 2>/dev/null | awk '{for(i=1;i<=NF;i++){if(\$i=="from"){print \$(i+1)}}}' | sort | uniq -c | sort -nr | head -20
echo "=== FAILED (count) ==="; grep -hcE 'Failed password' /var/log/auth.log /var/log/auth.log.1 2>/dev/null
echo "=== INVALID USERS ==="; grep -hE 'Invalid user' /var/log/auth.log* 2>/dev/null | awk '{for(i=1;i<=NF;i++){if(\$i=="from"){print \$(i+1)}}}' | sort | uniq -c | sort -nr | head -20
echo "=== SUDO ==="; grep -hE 'sudo:|su:' /var/log/auth.log* 2>/dev/null | tail -30
echo "=== LAST ==="; last -F | head -40
echo "=== LASTB ==="; lastb -F 2>/dev/null | head -30
echo "=== LASTLOG ==="; lastlog 2>/dev/null | grep -v 'Never logged'
EOF

# --- 10. Malware hunting ---
echo "[*] (10/12) Malware ..."
run_remote "$OUTPUT_DIR/09_malware.txt" <<'EOF'
echo "=== EXECUTABLES EN TEMP ==="; find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -40
echo "=== HIDDEN DIRS /tmp ==="; ls -la /tmp/ 2>/dev/null | head -30
echo "=== NOMBRES DE MALWARE CONOCIDOS ==="; find / -xdev -type f \( -name 'kthreadd*' -o -name 'Xorg.X*' -o -name '*xmrig*' -o -name 'kdevtmpfsi' -o -name 'cnrig*' -o -name 'minerd*' -o -name 'systemd-update' -o -name 'libprocesshider*' -o -name 'kinsing' \) 2>/dev/null
echo "=== WALLETS CRYPTO ==="; grep -rE '4[A-Za-z0-9]{94}|8[A-Za-z0-9]{94}|0x[a-f0-9]{40}|bc1[q0-9][a-z0-9]{39,59}' /etc /root /var/spool/cron 2>/dev/null | grep -v moduli | head -20
echo "=== SUID/SGID ==="; find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
echo "=== STRINGS MINERIA EN CONFIGS ==="; grep -rlEi 'xmrig|stratum|donate-level|cryptonight|--coin=monero|pool\.' /etc /root /var/spool/cron 2>/dev/null
EOF

# --- 11. Rootkit ---
echo "[*] (11/12) Rootkit ..."
run_remote "$OUTPUT_DIR/10_rootkit.txt" <<'EOF'
echo "=== LD.SO.PRELOAD ==="; cat /etc/ld.so.preload 2>/dev/null
echo "=== LD_PRELOAD EN /proc ==="; for p in /proc/[0-9]*/environ; do grep -l LD_PRELOAD "$p" 2>/dev/null; done
echo "=== HIDDEN PROCS (ps vs /proc) ==="; ps_count=$(ps -e --no-headers | wc -l); proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l); echo "ps=$ps_count proc=$proc_count diff=$((proc_count-ps_count))"
echo "=== LSMOD ==="; lsmod
echo "=== MODULE SIGNERS ==="; for m in $(awk '{print $1}' /proc/modules); do sig=$(modinfo "$m" 2>/dev/null | grep -i signer); echo "$m : ${sig:-NO-SIGNER}"; done
echo "=== DPKG VERIFY (coreutils) ==="; dpkg --verify 2>/dev/null | grep -E '(ps|ls|ss|top|netstat|find)$'
echo "=== DEBSUMS ==="; debsums -c 2>/dev/null | grep -E '/(ps|ls|top|ss|netstat|find)$'
EOF

# --- 12. Malfunction ---
echo "[*] (12/12) Malfunction ..."
run_remote "$OUTPUT_DIR/11_malfunction.txt" <<EOF
echo "=== FAILED UNITS ==="; systemctl list-units --type=service --state=failed --no-pager 2>/dev/null
echo "=== JOURNAL ERR (window) ==="; journalctl -p err --since "${SINCE}" --no-pager 2>/dev/null | tail -60
echo "=== OOM / PANIC / SEGFAULT ==="; grep -iE 'oom|kill|panic|segfault|hung task' /var/log/kern.log /var/log/syslog 2>/dev/null | tail -30
echo "=== DISK INODES ==="; df -ih
EOF

# --- Evidence manifest (chain of custody) ---
echo "[*] Hashing evidence ..."
( cd "$OUTPUT_DIR" && sha256sum $(find . -type f | sort) > evidence.sha256 )

echo "[*] Done. Evidence in: $OUTPUT_DIR"
