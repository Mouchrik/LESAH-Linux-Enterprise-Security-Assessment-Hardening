#!/usr/bin/env bash
#==============================================================================
# Advanced Linux Endpoint Security Toolkit (RHEL-compatible, patched)
# Developed by Hammza Mouchrik
# Version: 1.2
#==============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# REQUIREMENTS (check & enforce on RHEL)
#------------------------------------------------------------------------------

# Map binary -> package (RHEL/Fedora family)
pkg_for_cmd() {
  case "$1" in
    firewall-cmd) echo "firewalld" ;;
    sshd)         echo "openssh-server" ;;
    getenforce)   echo "policycoreutils" ;;            # provides getenforce
    semanage)     echo "policycoreutils-python-utils" ;;# semanage (RHEL 8/9)
    ss)           echo "iproute" ;;
    lsof)         echo "lsof" ;;
    awk)          echo "gawk" ;;
    grep)         echo "grep" ;;
    stat)         echo "coreutils" ;;
    find)         echo "findutils" ;;
    sed)          echo "sed" ;;
    lastlog)      echo "util-linux" ;;                 # lastlog from util-linux
    *)            echo "" ;;
  esac
}

# Choose package manager
pm_exec() {
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf -y "$@"
  elif command -v yum >/dev/null 2>&1; then
    sudo yum -y "$@"
  else
    return 127
  fi
}

ensure_pkgs_installed() {
  local pkgs=("$@")
  [[ ${#pkgs[@]} -eq 0 ]] && return 0
  print_status "INFO" "Installing packages (if missing): ${pkgs[*]}"
  pm_exec install "${pkgs[@]}" || print_status "WARNING" "Package install failed; please install manually: ${pkgs[*]}"
}

ensure_service_enabled() {
  local svc="$1"
  if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
    systemctl is-active --quiet "$svc" || sudo systemctl start "$svc" || true
  else
    sudo systemctl enable --now "$svc" 2>/dev/null || true
  fi
}

check_requirements() {
  print_status "INFO" "Checking system requirements & enforcing dependencies..."

  # 0) Directories (idempotent)
  mkdir -p "$REPORTS_DIR" "$BACKUPS_DIR"

  # 1) OS sanity (Linux + systemd)
  if [[ "$(uname -s)" != "Linux" ]]; then
    print_status "CRITICAL" "Unsupported OS (need Linux)."
    exit 1
  fi
  if ! pidof systemd >/dev/null 2>&1; then
    print_status "WARNING" "systemd not detected; some features may not work."
  fi

  # 2) Commands we rely on
  local required_cmds=(systemctl ss awk grep stat sed find)
  local recommended_cmds=(firewall-cmd sshd getenforce semanage lsof lastlog)
  local missing=() need_pkgs=()

  for c in "${required_cmds[@]}" "${recommended_cmds[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      missing+=("$c")
      local p; p="$(pkg_for_cmd "$c")"
      [[ -n "$p" ]] && need_pkgs+=("$p")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    print_status "WARNING" "Missing commands: ${missing[*]}"
    if [[ $EUID -ne 0 ]]; then
      print_status "CRITICAL" "Need root to install packages. Re-run with sudo."
      exit 1
    fi
    # De-duplicate package list
    mapfile -t need_pkgs < <(printf '%s\n' "${need_pkgs[@]}" | awk '!x[$0]++')
    ensure_pkgs_installed "${need_pkgs[@]}"
  else
    print_status "OK" "All required commands are present."
  fi

  # 3) Ensure key services are enabled/running (if available)
  if command -v firewall-cmd >/dev/null 2>&1; then
    ensure_service_enabled firewalld
  fi
  if command -v sshd >/dev/null 2>&1; then
    ensure_service_enabled sshd
  fi

  # 4) Helpful hints
  if ! command -v getenforce >/dev/null 2>&1; then
    print_status "INFO" "SELinux tooling missing; install 'policycoreutils'."
  fi
  if ! command -v semanage >/dev/null 2>&1; then
    print_status "INFO" "For SELinux policy tweaks, install 'policycoreutils-python-utils'."
  fi

  print_status "OK" "Requirements check complete."
}


#------------------------------------------------------------------------------
# Paths
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/reports"
BACKUPS_DIR="${SCRIPT_DIR}/backups"
LOG_FILE="${SCRIPT_DIR}/audit.log"

mkdir -p  "$REPORTS_DIR" "$BACKUPS_DIR"

#------------------------------------------------------------------------------
# Colors
#------------------------------------------------------------------------------
RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'

#------------------------------------------------------------------------------
# Findings & score (initialize explicitly for set -u)
#------------------------------------------------------------------------------
declare -A FINDINGS=()
declare -A SCORES=()
FINDINGS_INDEX=0
TOTAL_SCORE=0
MAX_POSSIBLE_SCORE=0

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"; }

print_status() {
  local status="$1" msg="$2"
  case "$status" in
    OK)       echo -e "[${GREEN}✓${NC}] $msg" ;;
    WARNING)  echo -e "[${YELLOW}⚠${NC}] $msg" ;;
    CRITICAL) echo -e "[${RED}✗${NC}] $msg" ;;
    INFO)     echo -e "[${BLUE}ℹ${NC}] $msg" ;;
  esac
}

add_finding() {
  local category="$1" severity="$2" title="$3" description="$4" remediation="${5:-}"

  # Use our own index to avoid ${#FINDINGS[@]} with set -u
  local key="${category}_${FINDINGS_INDEX}"
  FINDINGS_INDEX=$((FINDINGS_INDEX + 1))
  FINDINGS["$key"]="$severity|$title|$description|$remediation"

  case "$severity" in
    CRITICAL) SCORES["$key"]=0;  MAX_POSSIBLE_SCORE=$((MAX_POSSIBLE_SCORE + 25)) ;;
    HIGH)     SCORES["$key"]=5;  MAX_POSSIBLE_SCORE=$((MAX_POSSIBLE_SCORE + 20)) ;;
    MEDIUM)   SCORES["$key"]=10; MAX_POSSIBLE_SCORE=$((MAX_POSSIBLE_SCORE + 15)) ;;
    LOW)      SCORES["$key"]=15; MAX_POSSIBLE_SCORE=$((MAX_POSSIBLE_SCORE + 10)) ;;
    OK)       SCORES["$key"]=20; MAX_POSSIBLE_SCORE=$((MAX_POSSIBLE_SCORE + 20)) ;;
    *)        SCORES["$key"]=10; MAX_POSSIBLE_SCORE=$((MAX_POSSIBLE_SCORE + 10)) ;;
  esac

  TOTAL_SCORE=$((TOTAL_SCORE + SCORES["$key"]))
}

backup_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    local backup_name
    backup_name="$(basename "$file").backup.$(date +%s)"
    cp -a "$file" "${BACKUPS_DIR}/${backup_name}"
    log "Backed up $file to ${BACKUPS_DIR}/${backup_name}"
  fi
}

#------------------------------------------------------------------------------
# AUDIT MODULES (RHEL tuned)
#------------------------------------------------------------------------------

audit_system_info() {
  print_status "INFO" "Auditing system information..."
  local hostname os_info kernel uptime
  hostname=$(hostname -f 2>/dev/null || hostname)
  os_info=$( (source /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Unknown}") )
  kernel=$(uname -r)
  uptime=$(uptime -p 2>/dev/null || uptime)

  # Multiple kernels?
  local kcount
  kcount=$(ls /boot/vmlinuz-* 2>/dev/null | wc -l || echo 0)
  if [[ "$kcount" -gt 1 ]]; then
    add_finding "system" "MEDIUM" "Multiple installed kernels" \
      "Detected $kcount kernels. Current: $kernel" \
      "RHEL 8/9: 'dnf remove --oldinstallonly'. With yum-utils: 'package-cleanup --oldkernels --count=1'."
  else
    add_finding "system" "OK" "Kernel inventory OK" "Single active kernel: $kernel" ""
  fi

  SYSTEM_INFO="Hostname: $hostname<br>OS: $os_info<br>Kernel: $kernel<br>Uptime: $uptime"
}

audit_network_security() {
  print_status "INFO" "Auditing network security..."

  # Listening ports
  local open_ports
  open_ports=$(ss -tulnH 2>/dev/null | wc -l || echo 0)
  if   [[ $open_ports -gt 10 ]]; then
    add_finding "network" "HIGH" "High port exposure" \
      "Found $open_ports listening sockets." \
      "List ports: ss -tuln; disable unused services: systemctl disable --now <service>."
  elif [[ $open_ports -gt 5 ]]; then
    add_finding "network" "MEDIUM" "Moderate port exposure" \
      "Found $open_ports listening sockets." \
      "Reduce attack surface: review 'systemctl list-unit-files --type=service'."
  else
    add_finding "network" "OK" "Port exposure acceptable" "Found $open_ports listening sockets." ""
  fi

  # Dangerous ports
  local bad=(23 21 513 514 515 111 135 139 445 69 79 512)
  for p in "${bad[@]}"; do
    if ss -tulnH | awk '{print $5}' | grep -qE "[:.]${p}\$"; then
      add_finding "network" "CRITICAL" "Insecure service port open ($p)" \
        "Detected listening on port $p (legacy/insecure protocol)." \
        "Identify owner: ss -tulnp | grep :$p ; then stop/disable it."
    fi
  done

  # Firewall (RHEL: firewalld)
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    add_finding "network" "OK" "Firewall active" "firewalld is running." ""
  else
    add_finding "network" "CRITICAL" "No active firewall" \
      "firewalld is stopped or missing." \
      "Enable firewall: systemctl enable --now firewalld; allow required services via firewall-cmd."
  fi
}

audit_ssh_security() {
  print_status "INFO" "Auditing SSH security..."
  local sshd_config="/etc/ssh/sshd_config"

  if ! command -v sshd >/dev/null 2>&1; then
    add_finding "ssh" "HIGH" "sshd not installed" \
      "OpenSSH server not found." \
      "Install: dnf -y install openssh-server; systemctl enable --now sshd."
    return
  fi
  [[ -f "$sshd_config" ]] || {
    add_finding "ssh" "HIGH" "SSH config missing" \
      "File $sshd_config not found." \
      "Reinstall OpenSSH server: dnf -y reinstall openssh-server."
    return
  }

  # Effective config
  local prl="unknown" pwa="unknown" port="22"
  if sshd -T >/dev/null 2>&1; then
    
    pwa=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')
    port=$(sshd -T 2>/dev/null | awk '/^port /{print $2}')
  else
    
    pwa=$(grep -Ei '^\s*PasswordAuthentication\s+' "$sshd_config" | awk '{print tolower($2)}' || true)
    port=$(grep -Ei '^\s*Port\s+' "$sshd_config" | awk '{print $2}' || echo "22")
  fi


  if [[ "${pwa:-yes}" != "no" ]]; then
    add_finding "ssh" "HIGH" "Password auth enabled" \
      "PasswordAuthentication is not 'no' (effective: ${pwa})." \
      "Set key-only: sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config; sshd -t && systemctl reload sshd."
  else
    add_finding "ssh" "OK" "Key-only authentication" "PasswordAuthentication no" ""
  fi

  if [[ "${port:-22}" == "22" ]]; then
    add_finding "ssh" "MEDIUM" "Default SSH port" \
      "SSH listens on 22 (commonly scanned)." \
      "Optionally change: sed -i 's/^#*Port .*/Port 2222/' /etc/ssh/sshd_config; firewall-cmd --add-port=2222/tcp --permanent; firewall-cmd --reload; sshd -t && systemctl reload sshd."
  else
    add_finding "ssh" "OK" "Non-default SSH port" "SSH port is $port" ""
  fi
}

audit_user_accounts() {
  print_status "INFO" "Auditing user accounts..."
  local root_dupes sudo_nopw

  # --- Extra UID 0 users (besides root)
  root_dupes=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd || true)
  if [[ -n "$root_dupes" ]]; then
    add_finding "users" "CRITICAL" "Additional UID 0 users" \
      "UID 0 accounts besides root: $root_dupes" \
      "Lock or remove after validation: usermod -L <user> ; userdel <user>."
  else
    add_finding "users" "OK" "No extra root users" "Only 'root' has UID 0." ""
  fi

  # --- Empty passwords: only flag human users (UID >= 1000) with truly empty field
  # Get human users
  local human_users
  human_users=$(awk -F: '($3>=1000 && $1!="nobody"){print $1}' /etc/passwd 2>/dev/null || true)

  # Users with truly empty password field (not '*' or '!' which mean locked)
  local empty_pw_all empty_pw_humans
  empty_pw_all=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)

  # Intersect empty_pw_all ∩ human_users
  empty_pw_humans=$(printf '%s\n' $empty_pw_all | grep -Fx -f <(printf '%s\n' $human_users) 2>/dev/null || true)

  if [[ -n "$empty_pw_humans" ]]; then
    add_finding "users" "CRITICAL" "Accounts without passwords" \
      "Human accounts with empty password field: $empty_pw_humans" \
      "Set strong passwords or lock accounts: passwd <user>  /  usermod -L <user>."
  else
    add_finding "users" "OK" "No empty password accounts" \
      "All human accounts have passwords. (System accounts with '!' or '*' are locked and safe.)" ""
  fi

  # --- Passwordless sudo (ignore commented lines)
  if [[ -f /etc/sudoers ]]; then
    sudo_nopw=$(grep -Er "^[[:space:]]*[^#].*NOPASSWD:" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
    if [[ -n "$sudo_nopw" ]]; then
      add_finding "users" "HIGH" "Passwordless sudo present" \
        "Found active NOPASSWD entries in sudoers." \
        "Review via 'visudo' and require passwords for sudo."
    else
      add_finding "users" "OK" "Sudo requires password" "No active NOPASSWD entries." ""
    fi
  fi
}


audit_file_permissions() {
  print_status "INFO" "Auditing critical file permissions..."
  local files=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config")

  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    local perms; perms=$(stat -c "%a" "$f")
    case "$f" in
      /etc/shadow)
        if [[ "$perms" != "640" && "$perms" != "600" ]]; then
          add_finding "permissions" "CRITICAL" "/etc/shadow perms weak" \
            "Perms are $perms (expected 640/600)" \
            "chmod 640 /etc/shadow"
        else
          add_finding "permissions" "OK" "Shadow perms OK" "Perms: $perms" ""
        fi
        ;;
      /etc/sudoers)
        if [[ "$perms" != "440" ]]; then
          add_finding "permissions" "HIGH" "/etc/sudoers perms weak" \
            "Perms are $perms (expected 440)" \
            "chmod 440 /etc/sudoers"
        else
          add_finding "permissions" "OK" "Sudoers perms OK" "Perms: $perms" ""
        fi
        ;;
    esac
  done

  local ww
  ww=$(find /etc -type f -perm -002 2>/dev/null | head -5 || true)
  if [[ -n "$ww" ]]; then
    add_finding "permissions" "HIGH" "World-writable files in /etc" \
      "Examples: $(echo "$ww" | tr '\n' ' ')" \
      "Fix: find /etc -type f -perm -002 -exec chmod o-w {} \\;"
  else
    add_finding "permissions" "OK" "No world-writable files in /etc" "Good baseline." ""
  fi
}

audit_selinux() {
  print_status "INFO" "Auditing SELinux..."
  if command -v getenforce >/dev/null 2>&1; then
    local st; st=$(getenforce)
    case "$st" in
      Enforcing)
        add_finding "selinux" "OK" "SELinux Enforcing" "Policies enforced." ""
        ;;
      Permissive)
        add_finding "selinux" "MEDIUM" "SELinux Permissive" \
          "Logging only; not enforcing." \
          "Set enforcing: setenforce 1; persist via /etc/selinux/config (SELINUX=enforcing)."
        ;;
      Disabled)
        add_finding "selinux" "HIGH" "SELinux Disabled" \
          "Completely disabled." \
          "Re-enable in /etc/selinux/config (SELINUX=enforcing) and reboot (plan change)."
        ;;
    esac
  else
    add_finding "selinux" "MEDIUM" "SELinux tools missing" \
      "getenforce not found." \
      "Install: dnf -y install selinux-policy-targeted setools-console."
  fi
}

audit_services() {
  print_status "INFO" "Auditing running services..."
  local bad_svcs=(telnet rsh rlogin vsftpd finger talk tftp)
  local found=false
  for s in "${bad_svcs[@]}"; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
      add_finding "services" "CRITICAL" "Insecure service running: $s" \
        "'$s' uses insecure/legacy protocols." \
        "Disable: systemctl disable --now $s"
      found=true
    fi
  done
  [[ "$found" == false ]] && add_finding "services" "OK" "No insecure legacy services" "No telnet/rsh/rlogin/tftp/etc active." ""

  local active_count
  active_count=$(systemctl list-units --type=service --state=active 2>/dev/null | grep -c ' loaded active ' || echo 0)
  if [[ "$active_count" -gt 30 ]]; then
    add_finding "services" "MEDIUM" "Many active services" \
      "$active_count active services; consider minimizing surface." \
      "Review: systemctl list-unit-files --type=service"
  fi
}

#------------------------------------------------------------------------------
# HTML REPORT (safe counters)
#------------------------------------------------------------------------------

generate_html_report() {
  # Detect primary server IP (first non-loopback IPv4)
  SERVER_IP=$(hostname -I | awk '{print $1}')

  local count=$(ls "$REPORTS_DIR"/security_report_$(date +%Y%m%d)_*.html 2>/dev/null | wc -l)

# Increment count (so first report is 1, then 2, etc.)
  local next=$((count + 1))

# Pad with zeros (e.g., 001, 002, 010, 123)
  local next=$(printf "%03d" "$next")

# Final report filename
  # capture hostname safely (avoid dots/spaces in filename)
local hn
  hn=$(hostname -s 2>/dev/null || hostname)
  hn=${hn//[^a-zA-Z0-9_-]/_}   # sanitize (replace weird chars with "_")

local report_file="${REPORTS_DIR}/security_report_${hn}_$(date +%Y%m%d)_${next}_${SERVER_IP}.html"


  local final_score=0
  if [[ "$MAX_POSSIBLE_SCORE" -gt 0 ]]; then
    final_score=$((TOTAL_SCORE * 100 / MAX_POSSIBLE_SCORE))
  fi

  # Safe counters even if arrays are empty
  local total_findings critical_count ok_count
  total_findings=$(printf '%s\n' "${!FINDINGS[@]}" | wc -l)
  critical_count=$(printf '%s\n' "${FINDINGS[@]}" 2>/dev/null | grep -c '^CRITICAL|' || true)
  ok_count=$(printf '%s\n' "${FINDINGS[@]}" 2>/dev/null | grep -c '^OK|' || true)

  print_status "INFO" "Generating HTML report: $report_file"

  cat > "$report_file" << 'HEAD'
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Linux Security Audit Report</title>
<style>
body{font-family:Segoe UI,Tahoma,Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5}
.container{max-width:1200px;margin:0 auto;background:#fff;border-radius:8px;box-shadow:0 4px 6px rgba(0,0,0,.1)}
.header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:30px;border-radius:8px 8px 0 0}
.header h1{margin:0;font-size:2.2em}
.meta{margin-top:8px;opacity:.9}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;padding:24px;background:#f8f9fa}
.metric-card{background:#fff;padding:18px;border-radius:8px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,.05)}
.score{font-size:2.2em;font-weight:700;margin:8px 0}
.score.excellent{color:#28a745}.score.good{color:#ffc107}.score.poor{color:#dc3545}
.content{padding:24px}.section{margin-bottom:32px}.section h2{color:#333;border-bottom:3px solid #667eea;padding-bottom:8px}
.finding{margin:12px 0;padding:12px;border-radius:8px;border-left:4px solid}
.finding.ok{background:#d4edda;border-color:#28a745}
.finding.medium{background:#fff3cd;border-color:#ffc107}
.finding.high{background:#fde8d7;border-color:#fd7e14}
.finding.critical{background:#f8d7da;border-color:#dc3545}
.finding-title{font-weight:700;margin-bottom:6px}
.finding-desc{margin-bottom:8px;color:#555}
.remediation{background:#e3f2fd;padding:10px;border-radius:4px;font-family:monospace;font-size:.9em;margin-top:8px}
.severity-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75em;font-weight:700;color:#fff}
.severity-ok{background:#28a745}.severity-low{background:#17a2b8}.severity-medium{background:#ffc107;color:#212529}
.severity-high{background:#fd7e14}.severity-critical{background:#dc3545}
.footer{text-align:center;padding:16px;color:#666;border-top:1px solid #eee}
.system-info{background:#f8f9fa;padding:12px;border-radius:8px;margin-bottom:16px}
</style></head><body>
HEAD

  cat >> "$report_file" <<EOF
<div class="container">
  <div class="header">
    <h1>🔐 Security Audit Report </h1><br><h3>By Mouchrik Solutions</h3>
    <div class="meta">
      Generated: $(date)<br>
      Hostname: $(hostname -f 2>/dev/null || hostname)<br>
      IP address: ${SERVER_IP}
      Audited by: Linux Endpoint Security Toolkit v1.2 (RHEL)
    </div>
  </div>

  <div class="dashboard">
    <div class="metric-card">
      <div class="score $( if [[ $final_score -ge 80 ]]; then echo excellent; elif [[ $final_score -ge 60 ]]; then echo good; else echo poor; fi )">$final_score</div>
      <div>Security Score</div>
    </div>
    <div class="metric-card">
      <div class="score">$total_findings</div>
      <div>Total Findings</div>
    </div>
    <div class="metric-card">
      <div class="score" style="color:#dc3545;">$critical_count</div>
      <div>Critical Issues</div>
    </div>
    <div class="metric-card">
      <div class="score" style="color:#28a745;">$ok_count</div>
      <div>Passed Checks</div>
    </div>
  </div>

  <div class="content">
    <div class="system-info">
      <strong>System Information:</strong><br>
      $SYSTEM_INFO
    </div>
EOF

  local categories=(system network ssh users permissions selinux services)
  local names=("System" "Network Security" "SSH Security" "User Accounts" "File Permissions" "SELinux" "Services")

  for i in "${!categories[@]}"; do
    local c="${categories[$i]}" name="${names[$i]}"
    echo "<div class=\"section\"><h2>${name}</h2>" >> "$report_file"
    local any=false
    for key in "${!FINDINGS[@]}"; do
      [[ "$key" == "${c}_"* ]] || continue
      any=true
      IFS='|' read -r severity title desc remediation <<< "${FINDINGS[$key]}"
      local css=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
      cat >> "$report_file" <<EOF
      <div class="finding ${css}">
        <div class="finding-title">
          <span class="severity-badge severity-${css}">${severity}</span> ${title}
        </div>
        <div class="finding-desc">${desc}</div>
EOF
      [[ -n "$remediation" ]] && echo "<div class=\"remediation\"><strong>Remediation:</strong><br>${remediation}</div>" >> "$report_file"
      echo "</div>" >> "$report_file"
    done
    [[ "$any" == false ]] && echo "<p>No findings in this category.</p>" >> "$report_file"
    echo "</div>" >> "$report_file"
  done

  cat >> "$report_file" <<'TAIL'
  </div>
  <div class="footer"><p>Report generated by Linux Endpoint Security Toolkit (RHEL)</p></div>
</div>
</body></html>
TAIL

  print_status "OK" "HTML report generated: $report_file"
  echo "Final Security Score: $final_score/100"
  echo "$(date '+%Y-%m-%d %H:%M:%S'),$final_score" >> "${REPORTS_DIR}/score_history.csv"
}

#------------------------------------------------------------------------------
# REMEDIATION (safe subset)
#------------------------------------------------------------------------------

apply_remediations() {
  print_status "INFO" "Applying automatic remediations (safe subset)..."
  local applied=0
  local changed_fw_rules=0


  # --- 1) Firewall: ensure firewalld is running
  if ! systemctl is-active --quiet firewalld; then
    print_status "INFO" "Enabling firewalld"
    systemctl enable --now firewalld || print_status "WARNING" "Failed to enable firewalld"
    ((applied++))
  fi

  # --- 2) /etc/shadow permissions
  if [[ -f /etc/shadow ]]; then
    local sp; sp=$(stat -c "%a" /etc/shadow)
    if [[ "$sp" != "640" && "$sp" != "600" ]]; then
      print_status "INFO" "Fixing /etc/shadow permissions"
      chmod 600 /etc/shadow || true
      ((applied++))
    fi
  fi

  # --- 3) Disable insecure legacy services (if installed/running)
  # These are typical owners of dangerous cleartext protocols
  local bad_svcs=(telnet rsh rlogin vsftpd finger talk tftp)
  for s in "${bad_svcs[@]}"; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
      print_status "INFO" "Disabling insecure service: $s"
      systemctl disable --now "$s" || print_status "WARNING" "Could not disable $s"
      ((applied++))
    fi
  done

   # ---  For each *open* bad port, disable/mask the likely owning services
  local bad_ports=(23 21 513 514 515 111 135 139 445 69 79 512)

  # map: port -> candidate services/sockets
  declare -A port_services=(
    [21]="vsftpd ftp"
    [23]="telnet"
    [69]="tftp tftp.socket"
    [79]="finger"
    [111]="rpcbind rpcbind.socket nfs-server nfs-mountd rpc-statd rpc-gssd rpc-idmapd"
    [135]="rpcbind"
    [139]="smbd nmbd samba"
    [445]="smbd samba"
    [512]="rexec"
    [513]="rsh"
    [514]="rlogin"
    [515]="cups lpd"
  )

  # collect listening ports (tcp/udp)
  local open_ports
  open_ports=$(ss -tulnH | awk '{print $1,$5}' | sed -E 's/.*[:.]([0-9]+)$/\1/' || true)

  for p in "${bad_ports[@]}"; do
    if echo "$open_ports" | grep -qw "$p"; then
      print_status "INFO" "Port $p is listening → disabling related services"
      for svc in ${port_services[$p]:-}; do
        # Try both .service and .socket units (idempotent)
        if systemctl list-unit-files | grep -qE "^${svc}(\.service|\.socket)?\s"; then
          systemctl disable --now "${svc}.service" 2>/dev/null || true
          systemctl disable --now "${svc}.socket"  2>/dev/null || true
          systemctl mask         "${svc}.service"  2>/dev/null || true
          systemctl mask         "${svc}.socket"   2>/dev/null || true
          print_status "INFO" "Disabled & masked: ${svc}"
        fi
      done

      # Extra hardening if 111 is open (rpcbind/NFS family)
      if [[ "$p" == "111" ]]; then
        systemctl disable --now rpcbind.socket rpcbind 2>/dev/null || true
        systemctl mask rpcbind.socket rpcbind 2>/dev/null || true
        for u in nfs-server nfs-mountd rpc-statd rpc-gssd rpc-idmapd; do
          systemctl disable --now "$u" 2>/dev/null || true
          systemctl mask "$u" 2>/dev/null || true
        done
      fi
      ((applied++))
    fi
  done

  # --- 4) Firewalld: add DROP rules only for *open* bad ports (avoid duplicates)
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    print_status "INFO" "Applying firewalld drop rules for detected insecure open ports"
    local blocked=0
    local rr current_rr
    current_rr=$(firewall-cmd --list-rich-rules 2>/dev/null || true)

    for p in "${bad_ports[@]}"; do
      if echo "$open_ports" | grep -qw "$p"; then
        # tcp
        rr="rule family=ipv4 port port=$p protocol=tcp drop"
        if ! grep -qF "$rr" <<<"$current_rr"; then
          firewall-cmd --permanent --add-rich-rule="$rr" 1>/dev/null 2>&1 || true
          ((blocked++))
        fi
        # udp
        rr="rule family=ipv4 port port=$p protocol=udp drop"
        if ! grep -qF "$rr" <<<"$current_rr"; then
          firewall-cmd --permanent --add-rich-rule="$rr" 1>/dev/null 2>&1 || true
          ((blocked++))
        fi
      fi
    done

    if (( blocked > 0 )); then
      firewall-cmd --reload 1>/dev/null 2>&1 || true
      print_status "OK" "Firewalld hardened: $blocked rule(s) added for open insecure port(s)"
      ((applied+=blocked))
    else
      print_status "OK" "No new firewall rules needed (none of the bad ports were open or rules already exist)"
    fi
  else
    print_status "WARNING" "firewalld not active or not present; skipping firewall rules"
  fi


  print_status "OK" "Applied $applied remediation(s)"
}


#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------

run_audit() {
  print_status "INFO" "Starting security audit..."
  audit_system_info
  audit_network_security
  audit_ssh_security
  audit_user_accounts
  audit_file_permissions
  audit_selinux
  audit_services
  print_status "OK" "Security audit completed"
}

show_help() {
  cat << 'EOF'
Advanced Linux Endpoint Security Toolkit (RHEL)

Usage: ./security_audit_rhel.sh [OPTIONS]

Options:
  --audit         Run security audit (default)
  --fix           Apply safe automatic remediations, then report
  --report-only   Generate HTML report from current findings (after an audit)
  --help          Show this help

Reports: ./reports/
Backups: ./backups/
Logs   : ./audit.log
EOF
}

main() {
  local action="audit"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fix)         action="fix"; shift ;;
      --report-only) action="report"; shift ;;
      --audit)       action="audit"; shift ;;
      --help)        show_help; exit 0 ;;
      *) echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
  done

  if [[ $EUID -ne 0 ]]; then
    print_status "WARNING" "Not running as root. Some checks may be limited."
  fi

  log "Security audit started (action=$action)"
  case "$action" in
    audit)   run_audit; generate_html_report ;;
    fix)     run_audit; apply_remediations; generate_html_report ;;
    report)  if [[ ${#FINDINGS[@]} -eq 0 ]]; then
               print_status "WARNING" "No findings in memory. Run --audit first."
               exit 1
             fi
             generate_html_report ;;
  esac
  log "Security audit completed"
}

main "$@"
