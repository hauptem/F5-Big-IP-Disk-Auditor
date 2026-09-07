#!/bin/bash
# =============================================================================
# F5-Big-IP-Disk-Auditor
# =============================================================================
# Version: 1.0
# Author: Eric Haupt
# Released under the MIT License. See LICENSE file for details.
# https://github.com/hauptem/F5-Big-IP-Disk-Auditor
#
# Read-only disk space report for F5 BIG-IP. 
#
# Usage: ./F5-Big-IP-Disk-Audit.sh [--no-color] [--log <path>] [--html [<path>]]
#        [-y|--yes|--noconfirm]
#
#   --no-color      disable ANSI color in terminal output
#   --log <path>    append a plain-text copy of the report
#   --html [<path>] write a standalone HTML report instead of printing;
#                   default ./F5-Big-IP-Disk-Audit-Report-YYYYMMDD-HHMMSS.html
#   --noconfirm     skip the confirmation prompt (alias: -y, --yes)
#
# =============================================================================

set -u

#=============================================================================
# Configuration
#=============================================================================

# Scan lists. Each accepts a space-separated environment override, for example
# PCAP_DIRS="/shared/tmp /var/tmp/captures" ./F5-Big-IP-Disk-Audit.sh
read -r -a RELEVANT_MOUNTS <<< "${MOUNTS:-/ /config /usr /var /shared /var/log}"
read -r -a MAINT_FILE_DIRS <<< "${MAINT_DIRS:-/shared/tmp /var/tmp /var/core /shared/core}"
read -r -a PCAP_SCAN_DIRS  <<< "${PCAP_DIRS:-/shared/tmp /var/tmp /tmp /root /home /config /var/log/tcpdump}"
read -r -a UCS_SCAN_DIRS   <<< "${UCS_DIRS:-/var/local/ucs /shared/tmp /var/tmp /config /root /home}"
TOP_N=${TOP_N:-15}
RULE_WIDTH=95
EPSEC_IMAGE_DIR="/shared/apm/images"
EPSEC_FILESTORE_GLOB="/config/filestore/files_d/*_d/epsec_package_d"

#=============================================================================
# Argument parsing
#=============================================================================

USE_COLOR=1
LOG_FILE=""
HTML_FILE=""
AUTO_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-color) USE_COLOR=0; shift ;;
        --log)
            [[ $# -ge 2 ]] || { echo "--log requires a path" >&2; exit 2; }
            LOG_FILE="$2"; shift 2 ;;
        --html)
            if [[ $# -ge 2 && "$2" != -* ]]; then
                HTML_FILE="$2"; shift 2
            else
                HTML_FILE="./F5-Big-IP-Disk-Audit-Report-$(date '+%Y%m%d-%H%M%S').html"; shift
            fi ;;
        -y|--yes|--noconfirm) AUTO_YES=1; shift ;;
        -h|--help)
            # header block: comment lines from line 3 to the first blank line,
            # banner rules omitted
            awk 'NR >= 3 && !/^#/ {exit} NR >= 3 && !/^# ===/ {sub(/^# ?/, ""); print}' "$0"
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ ! -t 1 || -n "$HTML_FILE" ]] && USE_COLOR=0
if (( USE_COLOR == 1 )); then
    C_TXT=$'\033[0;97m'     # results: bright white
    C_HDR=$'\033[1;36m'     # section titles: bold cyan
    C_TTL=$'\033[1;93m'     # report title: bold yellow
    C_BLD=$'\033[1;97m'     # column headings, group labels
    C_DIM=$'\033[0;90m'     # what the section checks: gray
    C_RST=$'\033[0m'
else
    C_TXT="" C_HDR="" C_TTL="" C_BLD="" C_DIM="" C_RST=""
fi

#=============================================================================
# Output helpers
#=============================================================================

# Text mode writes to stdout. HTML mode accumulates fragments in HTML and
# writes nothing to stdout. Both modes append plain text to the --log file.

HTML=""
HTML_STATE="none"   # container currently open in the section: none | meta | table

# Uses sed rather than ${var//x/y}: bash 5.2 expands & in the replacement to
# the match.
html_esc() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# html_open <state>: closes the open container in the current section and
# opens <state>
TABLE_COLS=0
html_open() {
    [[ "$HTML_STATE" == "$1" ]] && return
    case "$HTML_STATE" in
        meta)  HTML+='</table>'$'\n' ;;
        table) HTML+='</tbody></table>'$'\n' ;;
    esac
    case "$1" in
        meta)  HTML+='<table class="meta">'$'\n' ;;
        table) HTML+='<table class="data">'$'\n' ;;
    esac
    HTML_STATE=$1
}

log_line() {
    [[ -n "$LOG_FILE" ]] || return 0
    printf '%s\n' "$*" | sed 's/\x1B\[[0-9;]*[mK]//g' >> "$LOG_FILE"
}

# emit <text>: plain line (banner, spacing). Check content uses the helpers
# below.
emit() {
    log_line "$*"
    [[ -n "$HTML_FILE" ]] && return 0
    printf '%s%s%s\n' "$C_TXT" "$*" "$C_RST"
}

rule() { printf '%*s' "$1" '' | tr ' ' "$2"; }

SECTION=0
header() {
    SECTION=$((SECTION+1))
    local title="Check $*"
    emit ""
    emit "${C_HDR}${title}${C_RST}"
    emit "${C_HDR}$(rule "$RULE_WIDTH" '-')${C_RST}"
    if [[ -n "$HTML_FILE" ]]; then
        html_open none
        (( SECTION > 1 )) && HTML+='</details>'$'\n'
        HTML+="<details id=\"check-${SECTION}\" open><summary>Check $(html_esc "$*")</summary>"$'\n'
    fi
}

# meta <key> <value> [html-value]: label/value line in the check description
# block
meta() {
    emit "${C_DIM}$(printf '  %-12s %s' "$1" "$2")${C_RST}"
    if [[ -n "$HTML_FILE" ]]; then
        html_open meta
        HTML+="<tr><th>$(html_esc "$1")</th><td>${3:-$(html_esc "$2")}</td></tr>"$'\n'
    fi
}

# F5 KB article titles, keyed by K number
declare -A KB=(
    [K14403]="Maintaining disk space on the BIG-IP system"
    [K23607394]="The /usr partition shows high disk space usage"
    [K33265170]="Deleting a boot location volume to free up disk space"
    [K34745165]="Managing software images on the BIG-IP system"
    [K21175584]="Removing unnecessary OPSWAT EPSEC packages from the BIG-IP APM system"
    [K13132]="Backing up and restoring BIG-IP configuration files with a UCS archive"
    [K41517018]="/var is nearly full, /var/log is not in /var"
    [K000092603]="Multiple EPSEC iso files in the system /config/filestore/files_d/Common_d/epsec_package_d/"
    [K000136089]="No space left on /var partition even after removing large files"
)
# ref <Knumber>...: article title with K number and URL; rendered as a link
# in HTML
ref() {
    local key="Reference:" k url
    (( $# > 1 )) && key="References:"
    for k in "$@"; do
        url="https://my.f5.com/manage/s/article/$k"
        meta "$key" "${KB[$k]:-$k} ($k)" "<a href=\"$url\">$(html_esc "${KB[$k]:-$k}") ($k)</a>"
        if [[ -n "$HTML_FILE" ]]; then
            log_line "$(printf '  %-12s %s' "" "$url")"
        else
            meta "" "$url"
        fi
        key=""
    done
}

# cmd <command>...: the command(s) the check executes, one per line
cmd() {
    local key="Command:" c
    (( $# > 1 )) && key="Commands:"
    for c in "$@"; do meta "$key" "$c" "<code>$(html_esc "$c")</code>"; key=""; done
}

# Check results. Text mode prints the preformatted line; HTML mode builds a
# table.
#   t_head  <text-line> <col>...   column headings
#   t_row   <text-line> <cell>...  one row; numeric cells are right-aligned
#   t_group <name>                 group label spanning the table
#   t_empty <message>              empty-result message
result() { emit "  $*"; }
label()  { emit "  ${C_BLD}$*${C_RST}"; }

html_cell() {
    local v=$1 cls=""
    [[ "$v" =~ ^[0-9][0-9.,]*[A-Za-z%]*$ ]] && cls=' class="num"'
    printf '<td%s>%s</td>' "$cls" "$(html_esc "$v")"
}

t_head() {
    label "$1"; shift
    [[ -n "$HTML_FILE" ]] || return 0
    html_open none; html_open table
    TABLE_COLS=$#
    HTML+='<thead><tr>'
    local c cls
    for c in "$@"; do
        cls=""
        case "$c" in Size|Used|Avail|Use%|Inodes|IUsed|IFree|IUse%|Version|Build|Files|PID) cls=' class="num"' ;; esac
        HTML+="<th${cls}>$(html_esc "$c")</th>"
    done
    HTML+='</tr></thead><tbody>'$'\n'
}

t_row() {
    result "$1"; shift
    [[ -n "$HTML_FILE" ]] || return 0
    html_open table
    (( TABLE_COLS == 0 )) && TABLE_COLS=$#
    HTML+='<tr>'
    local c; for c in "$@"; do HTML+="$(html_cell "$c")"; done
    HTML+='</tr>'$'\n'
}

t_group() {
    label "$1"
    [[ -n "$HTML_FILE" ]] || return 0
    html_open table
    HTML+="<tr class=\"group\"><td colspan=\"${TABLE_COLS:-1}\">$(html_esc "$1")</td></tr>"$'\n'
}

t_empty() {
    result "$1"
    [[ -n "$HTML_FILE" ]] || return 0
    if [[ "$HTML_STATE" == "table" ]]; then
        HTML+="<tr class=\"empty\"><td colspan=\"${TABLE_COLS:-1}\">$(html_esc "$1")</td></tr>"$'\n'
    else
        html_open none
        HTML+="<p class=\"empty\">$(html_esc "$1")</p>"$'\n'
    fi
}

# numfmt is absent on 13.x and 14.x (coreutils 8.4). The awk fallback
# reproduces numfmt --to=iec: round away from zero, one decimal below 10,
# integer at 10 and above.
human_bytes() {
    local b=$1
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$b" 2>/dev/null && return
    fi
    awk -v b="$b" 'BEGIN {
        split("B KB MB GB TB PB", u, " "); i = 1
        while (b >= 1024 && i < 6) { b /= 1024; i++ }
        if (i == 1) { printf "%d%s\n", b, u[i]; exit }
        if (b < 10) { v = int(b * 10); if (v < b * 10) v++; b = v / 10 }
        else        { v = int(b);      if (v < b)      v++; b = v }
        if (b >= 1024 && i < 6) { b = 1; i++ }
        if (b < 10) printf "%.1f%s\n", b, u[i]; else printf "%d%s\n", b, u[i]
    }'
}

version_field() {
    [[ -r /VERSION ]] || return
    sed -nE "s/^$1[[:space:]]*[:=][[:space:]]*(.*[^[:space:]])[[:space:]]*\$/\1/p" /VERSION 2>/dev/null | head -n 1
}

#=============================================================================
# Platform validation
#=============================================================================

# /VERSION uses "Key: Value" on 13.x and later, "Key=Value" on earlier releases
validate_platform() {
    local product
    product=$(version_field Product)
    [[ "$product" == "BIG-IP" ]] && return 0
    echo "This host is not a BIG-IP. No checks performed." >&2
    if [[ -r /VERSION ]]; then
        echo "/VERSION reports Product=${product:-<unset>}" >&2
    else
        echo "/VERSION is not present" >&2
    fi
    exit 3
}

#=============================================================================
# Confirmation prompt (terminal only, not logged)
#=============================================================================

# Clears the screen and scrollback without depending on TERM or the clear binary
clear_screen() { [[ -t 1 ]] && printf '\033[H\033[2J\033[3J'; }

confirm_execution() {
    (( AUTO_YES == 1 )) && return 0
    printf '%s\n' "${C_TTL}F5 BIG-IP Disk Audit Report${C_RST}"
    printf '%s\n' "Read-only disk usage and storage checks. Estimated runtime 10-60 seconds."
    local answer=""
    if [[ -t 0 ]]; then
        read -r -p "Continue? [y/N]: " answer
    elif [[ -r /dev/tty ]]; then
        read -r -p "Continue? [y/N]: " answer < /dev/tty
    else
        printf '%s\n' "No terminal available for confirmation. Use -y to bypass."
        exit 4
    fi
    case "$answer" in
        [yY]|[yY][eE][sS]) [[ -z "$HTML_FILE" ]] && clear_screen; return 0 ;;
        *) printf '%s\n' "Aborted."; exit 5 ;;
    esac
}

#=============================================================================
# Banner
#=============================================================================

get_hostname() {
    local hn=""
    [[ -r /proc/sys/kernel/hostname ]] && hn=$(< /proc/sys/kernel/hostname)
    [[ -z "$hn" ]] && hn=$(hostname 2>/dev/null)
    [[ -z "$hn" ]] && hn=$(uname -n 2>/dev/null)
    printf '%s' "${hn:-unknown}"
}

print_banner() {
    emit "${C_TTL}F5 BIG-IP Disk Audit Report${C_RST}"
    emit "${C_TTL}$(rule "$RULE_WIDTH" '=')${C_RST}"
    emit "$(printf '%-9s %s' "Host:" "$(get_hostname)")"
    emit "$(printf '%-9s %s' "Version:" "$(version_field Version; :)")"
    emit "$(printf '%-9s %s' "Date:" "$(date '+%Y-%m-%d %H:%M:%S %Z')")"
    [[ -n "$HTML_FILE" ]] && html_begin "$(get_hostname)" "$(version_field Version; :)"
}

html_begin() {
    local hn=$1 ver=$2
    HTML=$(cat <<EOF_HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>F5 BIG-IP Disk Audit Report - $(html_esc "$hn")</title>
<style>
  :root { --pad:32px; --mono:Consolas,"Cascadia Mono",Menlo,"DejaVu Sans Mono","Liberation Mono","Courier New",monospace; }
  html { scrollbar-gutter:stable; }
  @supports not (scrollbar-gutter:stable) { html { overflow-y:scroll; } }
  body { margin:0; background:#c4c3bf; color:#222; font:15px/1.5 "Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:1700px; margin:0 auto; padding:0 var(--pad); }
  header { height:40px; color:#dce0e4; background-image:repeating-linear-gradient(135deg,rgba(255,255,255,0) 0,rgba(255,255,255,.05) 2px,rgba(255,255,255,0) 4px),linear-gradient(#515b67,#768696); border-bottom:1px solid #5c5c5c; }
  header .wrap { padding:7px 0 0 39px; }
  h1 { margin:0; font-size:22px; font-weight:400; line-height:1.2; color:#dce0e4; font-family:"Helvetica Neue",Helvetica,Arial,sans-serif; }
  .run { display:inline-flex; align-items:flex-end; gap:40px; margin:12px 0; padding:8px 14px; font-size:14px; background:#fff; border:1px solid #a8a5a0; border-radius:4px; box-shadow:0 1px 2px rgba(0,0,0,.14); }
  .run dl { display:grid; grid-template-columns:max-content 1fr; gap:0 14px; margin:0; }
  .run dt { color:#444; } .run dd { margin:0; }
  .toggles { margin:0; font-size:13px; }
  .toggles a { cursor:pointer; margin-right:14px; }
  details { margin:0 0 8px; background:#fff; border:1px solid #a8a5a0; border-radius:4px; overflow:hidden; box-shadow:0 1px 2px rgba(0,0,0,.14); }
  summary { padding:2px 12px; font-size:14.5px; line-height:1.35; font-weight:600; color:#fff; background:#5f6c7a; cursor:pointer; list-style:none; user-select:none; }
  summary::-webkit-details-marker { display:none; }
  summary::before { content:"\25BE"; display:inline-block; width:22px; font-size:20px; line-height:1; vertical-align:-2px; color:#ffd633; }
  details:not([open]) summary::before { content:"\25B8"; }
  table.meta { border-collapse:collapse; width:calc(100% - 24px); margin:6px 12px 8px; background:#f3f2f0; font-size:13.5px; }
  table.meta th { text-align:left; vertical-align:top; color:#444; font-weight:normal; width:100px; padding:1px 12px; white-space:nowrap; }
  table.meta td { padding:1px 12px 1px 0; font-size:13.5px; }
  table.meta tr:first-child th, table.meta tr:first-child td { padding-top:4px; }
  table.meta tr:last-child th, table.meta tr:last-child td { padding-bottom:4px; }
  a { color:#2a4e73; }
  code { font-family:var(--mono); font-size:13px; color:#333; white-space:pre; }
  table.data { border-collapse:collapse; width:auto; margin:0 12px 8px; font-size:13.5px; font-family:var(--mono); }
  table.data th { text-align:left; font-weight:600; padding:0 16px 0 0; border-bottom:1px solid #cfd6de; white-space:nowrap; color:#555; }
  table.data td { padding:0 16px 0 0; vertical-align:top; white-space:nowrap; line-height:1.35; }
  table.data td:last-child, table.data th:last-child { padding-right:0; }
  table.data tbody tr:first-child td { padding-top:1px; }
  table.data td:last-child { white-space:normal; overflow-wrap:anywhere; }
  table.data td.num, table.data th.num { text-align:right; }
  table.data tr.group td { padding-top:6px; font-weight:600; color:#333; }
  table.data tr.empty td, p.empty { color:#222; }
  p.empty { margin:0 12px 8px; font-family:var(--mono); font-size:13.5px; }
  footer { margin:8px 0 16px; padding:6px 0; border-top:1px solid #a8a5a0; color:#222; font-size:13px; }
  @media print { body { background:#fff; } .wrap { max-width:none; padding:0 8px; } details { break-inside:avoid; border-color:#999; box-shadow:none; } .run { box-shadow:none; } header, summary, table.meta { -webkit-print-color-adjust:exact; print-color-adjust:exact; } }
</style>
</head>
<body>
<header><div class="wrap">
<h1>F5 BIG-IP Disk Audit Report</h1>
</div></header>
<div class="wrap">
<div class="run">
<dl>
  <dt>Host:</dt><dd><a href="https://$(html_esc "$hn")/">$(html_esc "$hn")</a></dd>
  <dt>Version:</dt><dd>$(html_esc "${ver:-unknown}")</dd>
  <dt>Date:</dt><dd>$(date '+%Y-%m-%d %H:%M:%S %Z')</dd>
</dl>
<p class="toggles"><a onclick="document.querySelectorAll('details').forEach(d=>d.open=true)">Expand all</a><a onclick="document.querySelectorAll('details').forEach(d=>d.open=false)">Collapse all</a></p>
</div>
<main>
EOF_HTML
)
    HTML+=$'\n'
}

html_finish() {
    [[ -n "$HTML_FILE" ]] || return 0
    html_open none
    (( SECTION > 0 )) && HTML+='</details>'$'\n'
    HTML+='</main>'$'\n'
    HTML+="<footer>End of report &middot; ${SECTION} checks completed &middot; $(date '+%Y-%m-%d %H:%M:%S %Z')</footer>
</div>
</body>
</html>
"
    if ! printf '%s' "$HTML" > "$HTML_FILE"; then
        echo "Cannot write HTML file: $HTML_FILE" >&2
        exit 2
    fi
}

#=============================================================================
# Reports
#=============================================================================

# report_df <flag> <col>...: df rows for RELEVANT_MOUNTS. With -P the device is
# the first field and the mount point the last.
report_df() {
    local flag=$1; shift
    local df_out hdr line m
    df_out=$(df "$flag" 2>/dev/null) || { t_empty "df $flag failed"; return; }
    hdr=$(head -n 1 <<< "$df_out")
    t_head "$hdr" "$@"
    for m in "${RELEVANT_MOUNTS[@]}"; do
        line=$(awk -v mp="$m" '$NF == mp' <<< "$df_out")
        [[ -n "$line" ]] || continue
        read -r -a f <<< "$line"
        t_row "$line" "${f[0]}" "${f[1]}" "${f[2]}" "${f[3]}" "${f[4]}" "${f[5]}"
    done
}

report_partition_space() {
    header "Partition free space"
    ref K14403 K23607394
    cmd "df -hP"
    emit ""
    report_df -hP "Filesystem" "Size" "Used" "Avail" "Use%" "Mounted on"
}

report_inode_usage() {
    header "Inode usage"
    ref K14403
    cmd "df -iP" "find /var -xdev -printf '%h\\n' | sort | uniq -c | sort -k 1 -nr | head -n $TOP_N"
    emit ""
    report_df -iP "Filesystem" "Inodes" "IUsed" "IFree" "IUse%" "Mounted on"
    emit ""
    # K14403: directories holding the most files in /var, the usual inode consumer
    local raw line
    raw=$(find /var -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -k 1 -nr | head -n "$TOP_N")
    [[ -n "$raw" ]] || { t_empty "No directories found in /var"; return; }
    t_head "$(printf '%9s  %s' Files Directory)" "Files" "Directory"
    while read -r line; do
        [[ -n "$line" ]] || continue
        t_row "$(printf '%9s  %s' "${line%% *}" "${line#* }")" "${line%% *}" "${line#* }"
    done <<< "$raw"
}

report_boot_volumes() {
    header "Boot location volumes"
    ref K33265170
    cmd "tmsh show sys software status"
    emit ""
    command -v tmsh >/dev/null 2>&1 || { t_empty "tmsh not available"; return; }
    local out
    out=$(tmsh show sys software status 2>/dev/null)
    [[ -n "$out" ]] || { t_empty "No output"; return; }
    # Column names come from the header row tmsh prints, so releases that add
    # columns after Status render them rather than folding them into Status.
    local -a cols=() f
    read -r -a cols <<< "$(awk '$1 == "Volume" {print; exit}' <<< "$out")"
    (( ${#cols[@]} >= 6 )) || cols=(Volume Product Version Build Active Status)
    local fmt="" c w t
    for c in "${cols[@]}"; do w=${#c}; (( w < 8 )) && w=8; fmt+="%-${w}s  "; done
    # shellcheck disable=SC2059
    t=$(printf "$fmt" "${cols[@]}"); t_head "${t%"${t##*[^ ]}"}" "${cols[@]}"
    local rows=0 line
    local n=${#cols[@]}
    while IFS= read -r line; do
        read -r -a f <<< "$line"
        [[ ${#f[@]} -ge 6 && "${f[0]}" =~ ^[A-Z]+[0-9]+\.[0-9]+$ ]] || continue
        # fields beyond the header count are folded into the last column
        if (( ${#f[@]} > n )); then
            f[n-1]="${f[*]:n-1}"; f=("${f[@]:0:n}")
        fi
        while (( ${#f[@]} < n )); do f+=(""); done
        # shellcheck disable=SC2059
        t=$(printf "$fmt" "${f[@]}"); t_row "${t%"${t##*[^ ]}"}" "${f[@]}"
        rows=$((rows+1))
    done <<< "$out"
    (( rows == 0 )) && t_empty "No volumes parsed from tmsh output"
}

# largest_files <dir>: top TOP_N files by size on the same filesystem
largest_files() {
    local raw line sz path
    raw=$(find "$1/" -xdev -type f -printf '%s %p\n' 2>/dev/null | sort -rn | head -n "$TOP_N")
    [[ -n "$raw" ]] || { t_empty "None found"; return; }
    t_head "$(printf '%9s  %s' Size Path)" "Size" "Path"
    while IFS= read -r line; do
        sz=$(human_bytes "${line%% *}"); path=${line#* }
        t_row "$(printf '%9s  %s' "$sz" "$path")" "$sz" "$path"
    done <<< "$raw"
}

report_largest_files_shared() {
    header "Largest files in /shared"
    ref K14403
    cmd "find /shared/ -xdev -type f -printf '%s %p\\n' | sort -rn | head -n $TOP_N"
    emit ""
    [[ -d /shared ]] || { t_empty "/shared not present"; return; }
    largest_files /shared
}

report_largest_files_var() {
    header "Largest files in /var"
    ref K14403
    cmd "find /var/ -xdev -type f -printf '%s %p\\n' | sort -rn | head -n $TOP_N"
    emit ""
    [[ -d /var ]] || { t_empty "/var not present"; return; }
    largest_files /var
}

# /var/log is its own volume (dat.log). find -xdev from /var never enters it,
# so it needs a separate walk.
report_largest_files_var_log() {
    header "Largest files in /var/log"
    ref K14403 K41517018
    cmd "find /var/log/ -xdev -type f -printf '%s %p\\n' | sort -rn | head -n $TOP_N"
    emit ""
    [[ -d /var/log ]] || { t_empty "/var/log not present"; return; }
    largest_files /var/log
}

report_iso_inventory() {
    header "ISO images in /shared/images"
    ref K34745165
    cmd "find /shared/images -maxdepth 2 -type f -name '*.iso'"
    emit ""
    [[ -d /shared/images ]] || { t_empty "/shared/images not present"; return; }
    local running_ver isos line sz path status
    running_ver=$(version_field Version)
    isos=$(find /shared/images -maxdepth 2 -type f -name '*.iso' -printf '%s %p\n' 2>/dev/null | sort -rn)
    [[ -n "$isos" ]] || { t_empty "None found"; return; }
    t_head "$(printf '%9s  %s' Size Path)" "Size" "Path" "Status"
    while IFS= read -r line; do
        sz=$(human_bytes "${line%% *}"); path=${line#* }; status=""
        [[ -n "$running_ver" && "$path" == *"-${running_ver}-"* ]] && status="running version"
        t_row "$(printf '%9s  %s%s' "$sz" "$path" "${status:+  ${C_HDR}<-- ${status}${C_RST}}")" "$sz" "$path" "$status"
    done <<< "$isos"
}

report_epsec_images() {
    header "EPSEC (APM Endpoint Security) packages"
    ref K21175584 K000092603
    cmd "find $EPSEC_IMAGE_DIR $EPSEC_FILESTORE_GLOB -maxdepth 1 -type f -name '*epsec*'" \
        "tmsh list apm epsec epsec-package one-line" \
        "tmsh show apm epsec software-status"
    emit ""
    local -A registered=() sysflag=() seen=()
    local active_ver="" n f
    if command -v tmsh >/dev/null 2>&1; then
        while read -r n f; do
            [[ -n "$n" ]] || continue
            registered[$n]=1; sysflag[$n]=$f
        done < <(tmsh list apm epsec epsec-package one-line 2>/dev/null \
                 | awk '$3=="epsec-package" {f="-"; for(i=1;i<=NF;i++) if($i=="system-package") f=$(i+1); print $4, f}')
        active_ver=$(tmsh show apm epsec software-status 2>/dev/null | awk '$1 ~ /^\// {print $2; exit}')
    fi
    local fmt='%-30s %7s  %-16s  %-16s  %-10s  %-10s  %s'
    local rows="" dir m sz dp tp path name loc reg act
    for dir in "$EPSEC_IMAGE_DIR" $EPSEC_FILESTORE_GLOB; do
        [[ -d "$dir" ]] || continue
        loc="filestore"; [[ "$dir" == "$EPSEC_IMAGE_DIR" ]] && loc="staged"
        while IFS= read -r m; do
            [[ -n "$m" ]] || continue
            read -r sz dp tp path <<< "$m"
            name=${path##*/}
            name=${name#:*:}                  # strip filestore prefix :Partition:
            name=$(sed -E 's/_[0-9]+_[0-9]+$//' <<< "$name")   # strip filestore suffix _id_rev
            reg=no; [[ -n "${registered[$name]:-}" ]] && reg=yes
            act=no; [[ -n "$active_ver" && "$name" == *"$active_ver"* ]] && act=yes
            rows+=$(printf '%s\t%s\t%s %s\t%s\t%s\t%s\t%s' \
                    "$name" "$(human_bytes "$sz")" "$dp" "$tp" "$loc" "$reg" "${sysflag[$name]:--}" "$act")$'\n'
            seen[$name]=1
        done < <(find "$dir" -maxdepth 1 -xdev -type f -name '*epsec*' \
                 -printf '%s %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -rn)
    done
    for name in "${!registered[@]}"; do
        [[ -n "${seen[$name]:-}" ]] && continue
        act=no; [[ -n "$active_ver" && "$name" == *"$active_ver"* ]] && act=yes
        rows+=$(printf '%s\t-\t-\t(file not found)\tyes\t%s\t%s' "$name" "${sysflag[$name]:--}" "$act")$'\n'
    done
    [[ -n "$rows" ]] || { t_empty "None found"; return; }
    # shellcheck disable=SC2059
    t_head "$(printf "$fmt" Package Size Date Location Registered SystemPkg Active)" \
           "Package" "Size" "Date" "Location" "Registered" "System package" "Active"
    while IFS=$'\t' read -r name sz dt loc reg sysp act; do
        [[ -n "$name" ]] || continue
        # shellcheck disable=SC2059
        t_row "$(printf "$fmt" "$name" "$sz" "$dt" "$loc" "$reg" "$sysp" "$act")" \
              "$name" "$sz" "$dt" "$loc" "$reg" "$sysp" "$act"
    done <<< "$rows"
}

# scan_by_glob <find-expr>... -- <dir>...: size, modified, path; grouped by
# directory. The find expression is passed as separate arguments so that
# patterns are never subject to pathname expansion in the working directory.
scan_by_glob() {
    local -a pattern=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do pattern+=("$1"); shift; done
    shift
    local dir matches m sz dp tp path found=""
    for dir in "$@"; do
        [[ -d "$dir" ]] || continue
        matches=$(find "$dir" -xdev -type f \( "${pattern[@]}" \) \
                  -printf '%s %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -rn)
        [[ -n "$matches" ]] || continue
        found+="$dir"$'\n'"$matches"$'\n'$'\x1f'$'\n'
    done
    [[ -n "$found" ]] || { t_empty "None found"; return; }
    t_head "$(printf '  %9s  %-16s  %s' Size Modified Path)" "Size" "Modified" "Path"
    local group=1
    while IFS= read -r m; do
        if [[ "$m" == $'\x1f' ]]; then group=1; continue; fi
        [[ -n "$m" ]] || continue
        if (( group )); then t_group "$m"; group=0; continue; fi
        read -r sz dp tp path <<< "$m"
        sz=$(human_bytes "$sz")
        t_row "$(printf '  %9s  %s %s  %s' "$sz" "$dp" "$tp" "$path")" "$sz" "$dp $tp" "$path"
    done <<< "$found"
}

report_ucs_files() {
    header "UCS configuration archives"
    ref K13132 K14403
    cmd "find ${UCS_SCAN_DIRS[*]} -xdev -type f -name '*.ucs'"
    emit ""
    scan_by_glob -name '*.ucs' -- "${UCS_SCAN_DIRS[@]}"
}

report_old_maintenance_files() {
    header "Maintenance files"
    ref K14403
    cmd "find ${MAINT_FILE_DIRS[*]} -xdev -type f \\( -name 'qkview-*' -o -name '*.qkview' -o -name '*.tar.gz' -o -name 'core.*' -o -name '*.core' -o -name '*.core.gz' \\)"
    emit ""
    scan_by_glob -name 'qkview-*' -o -name '*.qkview' -o -name '*.tar.gz' \
                 -o -name 'core.*' -o -name '*.core' -o -name '*.core.gz' -- "${MAINT_FILE_DIRS[@]}"
}

# Space held by files that were deleted while a process still has them open.
# df counts the blocks; find cannot see them. lsof +L1 selects open files with
# link count 0. Entries on tmpfs/none mounts and under /dev are skipped per
# K14403. Diagnostic only: releasing the space means restarting the holder.
report_deleted_open_files() {
    header "Deleted files still held open"
    ref K14403 K000136089
    cmd "lsof -nP +L1"
    emit ""
    command -v lsof >/dev/null 2>&1 || { t_empty "lsof not available"; return; }
    local skip
    skip=$(df -P 2>/dev/null | awk 'NR > 1 && ($1 == "none" || $1 == "tmpfs" || $1 == "devtmpfs") {print $NF}')
    local raw
    # One row per inode: a daemon often holds the same deleted file on
    # several descriptors.
    raw=$(lsof -nP +L1 -F pcftsnDi 2>/dev/null | awk -v skip="$skip" '
        BEGIN { n = split(skip, sk, "\n") }
        function flush(   i, key) {
            if (typ == "REG" && size > 0 && name ~ /^\// && name !~ /^\/dev\//) {
                for (i = 1; i <= n; i++) if (sk[i] != "" && index(name, sk[i] "/") == 1) return
                key = dev ":" ino
                if (key in seen) return
                seen[key] = 1
                printf "%s %s %s %s\n", size, cmd, pid, name
            }
        }
        /^p/ { flush(); pid = substr($0, 2); typ = ""; size = 0; name = ""; dev = ""; ino = "" }
        /^c/ { cmd = substr($0, 2) }
        /^f/ { flush(); typ = ""; size = 0; name = ""; dev = ""; ino = "" }
        /^t/ { typ = substr($0, 2) }
        /^s/ { size = substr($0, 2) + 0 }
        /^D/ { dev = substr($0, 2) }
        /^i/ { ino = substr($0, 2) }
        /^n/ { name = substr($0, 2); sub(/ \(deleted\)$/, "", name) }
        END  { flush() }' | sort -rn | head -n "$TOP_N")
    [[ -n "$raw" ]] || { t_empty "None found"; return; }
    local line sz proc pid path
    t_head "$(printf '%9s  %-16s %-7s %s' Size Process PID Path)" "Size" "Process" "PID" "Path"
    while read -r sz proc pid path; do
        [[ -n "$path" ]] || continue
        sz=$(human_bytes "$sz")
        t_row "$(printf '%9s  %-16s %-7s %s' "$sz" "$proc" "$pid" "$path")" "$sz" "$proc" "$pid" "$path"
    done <<< "$raw"
}

report_pcap_files() {
    header "Packet capture files"
    ref K14403
    cmd "find ${PCAP_SCAN_DIRS[*]} -xdev -type f \\( -name '*.pcap' -o -name '*.cap' -o -name '*.pcapng' \\)"
    emit ""
    scan_by_glob -name '*.pcap' -o -name '*.cap' -o -name '*.pcapng' -- "${PCAP_SCAN_DIRS[@]}"
}

#=============================================================================
# Main
#=============================================================================

validate_platform
# Administrator role with Advanced Shell is uid 0 on BIG-IP; anything else
# under-reports (find skips unreadable dirs, lsof sees only own processes).
(( EUID == 0 )) || echo "Warning: not running as root; results will be partial" >&2
if [[ -n "$LOG_FILE" ]]; then
    # A failed redirection on a { } group with commands inside does not fail the
    # group; probe with a bare : instead.
    if ! { : >> "$LOG_FILE"; } 2>/dev/null; then
        echo "Cannot write to log file: $LOG_FILE" >&2
        exit 2
    fi
    {
        echo ""
        echo "===== Run started: $(date '+%Y-%m-%d %H:%M:%S %Z') ====="
    } >> "$LOG_FILE"
fi
confirm_execution
if [[ -n "$HTML_FILE" ]] && ! { : >> "$HTML_FILE"; } 2>/dev/null; then
    echo "Cannot write HTML file: $HTML_FILE" >&2
    exit 2
fi
print_banner

# Capacity
report_partition_space
report_inode_usage
report_boot_volumes

# Where the space is: visible files per volume, then space no file accounts for
report_largest_files_shared
report_largest_files_var
report_largest_files_var_log
report_deleted_open_files

# What can be removed
report_iso_inventory
report_epsec_images
report_ucs_files
report_old_maintenance_files
report_pcap_files

emit ""
emit "${C_TTL}$(rule "$RULE_WIDTH" '=')${C_RST}"
emit "${C_TTL}End of report${C_RST}  ${SECTION} checks completed  $(date '+%Y-%m-%d %H:%M:%S %Z')"
emit "${C_TTL}$(rule "$RULE_WIDTH" '=')${C_RST}"
html_finish
[[ -n "$HTML_FILE" ]] && echo "Report written to $HTML_FILE"
exit 0
