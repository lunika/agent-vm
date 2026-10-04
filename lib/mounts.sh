# --- mounts: the shares a VM gets, and ~/.agent-vm/volumes --------------------

# Stage a single host file at <dst> via hardlink, falling back to copy if the
# source and destination live on different filesystems. Hardlinking keeps the
# content live-synced with the host (same inode) without exposing the source's
# parent directory to the VM. The copy fallback preserves the no-exposure
# property but loses live sync until the next VM (re)start.
_agent_vm_stage_file() {
  local src="$1" dst="$2"
  mkdir -p "$(dirname "$dst")" 2>/dev/null || return 1
  rm -f "$dst"
  if ln "$src" "$dst" 2>/dev/null; then
    return 0
  fi
  if cp -p "$src" "$dst" 2>/dev/null; then
    echo "Warning: Staged '${src}' via copy (cross-filesystem hardlink failed); live host changes will not propagate until VM (re)start." >&2
    return 0
  fi
  return 1
}

# 0 when the project directory <dir> matches <filter>, the 4th field of a
# ~/.agent-vm/volumes entry: a path, `~` expanded, where `*` matches anything,
# `/` included. A filter that is not absolute matches nothing, with a warning.
# `~user/...` is not expanded: it counts as not absolute.
_agent_vm_volume_matches() {
  local filter="$1" dir="$2"
  case "$filter" in
    "~"|"~/"*) filter="$HOME${filter#\~}" ;;
  esac
  [[ "$filter" == / ]] || filter="${filter%/}"
  if [[ "$filter" != /* ]]; then
    echo "Warning: Project filter '$1' (from ~/.agent-vm/volumes) is not an absolute path, skipping the entry." >&2
    return 1
  fi
  [[ "$dir" == $filter ]]
}

# A relative destination in ~/.agent-vm/volumes is inside the project. Prints
# its absolute path, after creating it on the host (a directory, or an empty
# file for a file source): virtiofs and 9p create mount points before the
# project is mounted, and --readonly refuses the write from the guest.
# No component may be ".." or a symlink: the agent can write the project, and
# mkdir would follow a link it planted there to anywhere on the host. Checked
# here for the message, and made with _agent_vm_nofollow, since the VM could
# swap a link in after the check.
_agent_vm_project_mountpoint() {
  local dir="$1" rel="$2" src="$3" p="$1" comp rest="$2/" norm=""
  while [[ -n "$rest" ]]; do
    comp="${rest%%/*}"
    rest="${rest#*/}"
    [[ -z "$comp" || "$comp" == . ]] && continue
    if [[ "$comp" == .. ]]; then
      echo "Warning: Mount destination '${rel}' (from ~/.agent-vm/volumes) goes out of the project with '..', skipping." >&2
      return 1
    fi
    p="$p/$comp"
    norm="${norm:+$norm/}$comp"
    if [[ -L "$p" ]]; then
      echo "Warning: Mount destination '${rel}' (from ~/.agent-vm/volumes) goes through a symlink in the project ($p), skipping." >&2
      return 1
    fi
  done
  if [[ "$p" == "$dir" ]]; then
    echo "Warning: Mount destination '${rel}' (from ~/.agent-vm/volumes) is the project itself, skipping." >&2
    return 1
  fi
  local op=touch st=0
  [[ -d "$src" ]] && op=mkdir
  _agent_vm_nofollow "$op" "$dir" "$norm" 2>/dev/null || st=$?
  case "$st" in
    0) ;;
    3)
      echo "Warning: Mount destination '${rel}' (from ~/.agent-vm/volumes) goes through a symlink in the project, or is not a $([[ "$op" == mkdir ]] && echo directory || echo file) there, skipping." >&2
      return 1 ;;
    *)
      command -v perl >/dev/null 2>&1 \
        || echo "Warning: perl is needed to create the mount point '$p' in the project without following symlinks." >&2
      echo "Warning: Cannot create the mount point '$p' (from ~/.agent-vm/volumes), skipping." >&2
      return 1 ;;
  esac
  printf '%s\n' "$p"
}

# The entries of ~/.agent-vm/volumes for the project <dir>, one per line,
# four fields separated by |, which none can hold: source (~ expanded,
# existing), destination (absolute and normalized, relative as written, or
# empty for the source's own path), mode (ro or rw), and the entry as
# source:destination:mode, for messages. Entries that cannot be used are
# skipped, with a warning on stderr. Nothing is created: that is
# _agent_vm_build_mounts_json's.
_agent_vm_volume_entries() {
  local host_dir="$1" raw line mounts_file="$AGENT_VM_STATE_DIR/volumes" why mp proj_mp seen_mps=$'\n'
  [[ -f "$mounts_file" ]] || return 0
  # Empty while asked: the memos are what the two functions read first.
  local _agent_vm_unsafe_refs _agent_vm_windows_memo="" _agent_vm_nocase_memo=""
  _agent_vm_on_windows && _agent_vm_windows_memo=1 || _agent_vm_windows_memo=0
  _agent_vm_fs_nocase && _agent_vm_nocase_memo=1 || _agent_vm_nocase_memo=0
  _agent_vm_unsafe_refs="$(_agent_vm_unsafe_ref_dirs)"
  proj_mp="$(_agent_vm_path_join / "$host_dir")"
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    line="${raw%%#*}"                                           # strip comments
    line="${line#"${line%%[![:space:]]*}"}"                     # trim leading whitespace
    line="${line%"${line##*[![:space:]]}"}"                     # trim trailing whitespace
    [[ -z "$line" ]] && continue
    # A control character (a tab, an ESC...) is invalid unescaped in the JSON
    # handed to limactl. The CR of a CRLF file went with the trim above.
    if [[ "$line" == *[[:cntrl:]]* ]]; then
      echo "Warning: Mount entry '${raw}' (from ~/.agent-vm/volumes) contains a control character, skipping." >&2
      continue
    fi
    # An optional 4th field, after an explicit mode, limits the entry to the
    # projects it matches: source:destination:mode:filter. An empty one
    # (`src:dst:rw:`) is refused, not read as "no filter": that would mount
    # an entry meant for one project in every project.
    local filter="" has_filter="" before="${line%:*}"
    if [[ "$line" == *:* && ( "$before" == *:ro || "$before" == *:rw ) ]]; then
      filter="${line##*:}"
      has_filter=1
      line="$before"
    fi
    if [[ -n "$has_filter" ]]; then
      if [[ -z "$filter" ]]; then
        echo "Warning: Mount entry '${raw}' (from ~/.agent-vm/volumes) has an empty project filter; refusing to mount it in every project. Skipping." >&2
        continue
      fi
      _agent_vm_volume_matches "$filter" "$host_dir" || continue
    fi
    # Parse source[:destination][:mode] syntax (like docker compose volumes).
    # The trailing mode segment is only recognized when it equals "ro" or
    # "rw": anything else is treated as a destination path.
    local src="$line" dst="" mode="ro" entry="$line"
    if [[ "$line" == *:ro || "$line" == *:rw ]]; then
      mode="${line##*:}"
      line="${line%:*}"
    fi
    if [[ "$line" == *:* ]]; then
      src="${line%%:*}"
      dst="${line#*:}"
    else
      src="$line"
    fi
    # A ':' left in the destination is a field out of place: a project
    # without a mode before it (`src:dst:/p`), a mode after it
    # (`src:dst:/p:rw`), a second mode, a fifth field. Read as a destination,
    # the entry would be mounted in every project, the project filter lost.
    if [[ "$dst" == *:* ]]; then
      echo "Warning: Mount entry '${raw}' (from ~/.agent-vm/volumes) does not read as source:destination:mode:project (the mode goes before the project, and is needed with one). Skipping." >&2
      continue
    fi
    src="${src/#\~/$HOME}"                                      # expand ~
    # Reject characters that would break the mounts JSON or the |-separated
    # lines this prints and the file mounts cache.
    if [[ "$src" == *[$'"\\\n|']* || "$dst" == *[$'"\\\n|']* ]]; then
      echo "Warning: Mount entry '${raw}' (from ~/.agent-vm/volumes) contains invalid characters (quote/backslash/newline/pipe), skipping." >&2
      continue
    fi
    if [[ ! -e "$src" ]]; then
      echo "Warning: Mount path '${src}' (from ~/.agent-vm/volumes) does not exist, skipping." >&2
      continue
    fi
    # What is refused as a project, refused as a volume (see
    # _agent_vm_unsafe_project), a repository's own folder only when the VM
    # could write it.
    if why="$(_agent_vm_unsafe_location "$src")" \
       || { [[ "$mode" == rw && -d "$src" ]] && why="$(_agent_vm_git_dir_share "$src")"; }; then
      echo "Warning: Mount path '${src}' (from ~/.agent-vm/volumes) $why, skipping." >&2
      continue
    fi
    # Where the VM sees it: the destination, or the source's own path, as
    # Lima takes it. At the project or above it, it would hide the project's
    # share. At another entry's place, Lima would merge the two into one
    # share, with the second one's mode.
    mp="${dst:-$src}"
    [[ "$mp" == /* ]] || mp="$host_dir/$mp"
    mp="$(_agent_vm_path_join / "$mp")"
    [[ -z "$dst" || "$dst" != /* ]] || dst="$mp"
    if [[ "${proj_mp%/}/" == "${mp%/}/"* ]]; then
      echo "Warning: Mount entry '${entry}' (from ~/.agent-vm/volumes) would be mounted at $mp, which covers the project, skipping." >&2
      continue
    fi
    if [[ "$seen_mps" == *$'\n'"$mp"$'\n'* ]]; then
      echo "Warning: Mount entry '${entry}' (from ~/.agent-vm/volumes) would be mounted at $mp, as an entry before it, skipping." >&2
      continue
    fi
    seen_mps="$seen_mps$mp"$'\n'
    printf '%s|%s|%s|%s\n' "$src" "$dst" "$mode" "$entry"
  done < "$mounts_file"
}

# The writable directories of ~/.agent-vm/volumes for the project <dir>, one
# per line: shares the VM can write besides the project. Read quietly: the
# start that mounts them says what is wrong with an entry.
_agent_vm_rw_volume_dirs() {
  local src dst mode entry
  while IFS='|' read -r src dst mode entry; do
    [[ "$mode" == rw && -d "$src" ]] && printf '%s\n' "$src"
  done <<< "$(_agent_vm_volume_entries "$1" 2>/dev/null)"
}

# _agent_vm_build_mounts_json <vm> <dir> [<writable>] [<names>]: the .mounts
# JSON array for `limactl edit --set`. The project <dir> first, writable
# unless <writable> is false, then the entries of ~/.agent-vm/volumes
# (`source[:destination][:ro|rw[:project]]`, ro by default).
# - <writable> false is --readonly, for every share, rw volumes included: a
#   writable volume holding the project would be a second way to write it.
#   Lima enforces `writable: false` on the host side, where root in the VM
#   cannot undo it, except on reverse-sshfs without readonlyNames (see
#   _agent_vm_mount_is_host_enforced).
# - <names> keeps names read-only on every share: a readonlyNames JSON array,
#   or 1 for the project's (see _agent_vm_readonly_names). The caller sets the
#   mount type that goes with it (see _agent_vm_mounts_expr).
# Single files are hardlinked into ~/.agent-vm/file-mounts/<vm>/, shared from
# there and listed in ~/.agent-vm/.agent-vm-file-mounts-<vm> for the bind in
# the VM.
_agent_vm_build_mounts_json() {
  local vm_name="$1" host_dir="$2" project_writable="${3:-true}" names="" sshfs_ro="" sshfs_rw=""
  case "${4:-}" in
    1)  names="$(_agent_vm_readonly_names "$host_dir")" ;;
    \[*) names="$4" ;;
  esac
  # sshfs's cache (cache: false is -o cache=no): with it, a file the host
  # adds, deletes or extends shows as it was for up to 20 seconds, and an
  # agent writing back what it read would undo the host's change. Off on the
  # writable shares (see _agent_vm_sshfs_cache_mode).
  if [[ -n "$names" ]]; then
    sshfs_ro=", \"sshfs\": {\"sftpDriver\": \"builtin\", \"readonlyNames\": $names}"
    sshfs_rw="$sshfs_ro"
    [[ "$(_agent_vm_sshfs_cache_mode)" == on ]] \
      || sshfs_rw=", \"sshfs\": {\"sftpDriver\": \"builtin\", \"cache\": false, \"readonlyNames\": $names}"
  fi
  local sshfs="$sshfs_ro"
  [[ "$project_writable" != true ]] || sshfs="$sshfs_rw"
  # Every entry names its mount point: agent-vm addresses the guest side by the
  # shell's spelling of the path (--workdir, the write probe), which on Windows
  # is not the C:/... form Lima reads the location in.
  local mounts_json="[{\"location\": \"$(_agent_vm_host_path "$host_dir")\", \"mountPoint\": \"${host_dir}\", \"writable\": ${project_writable}${sshfs}}"
  local file_mount_entries=()
  local file_mounts_cache="$AGENT_VM_STATE_DIR/.agent-vm-file-mounts-${vm_name}"

  local staging_idx=0 src dst mode line
  while IFS='|' read -r src dst mode line; do
    [[ -n "$src" ]] || continue
    if [[ -n "$dst" && "$dst" != /* ]]; then
      dst="$(_agent_vm_project_mountpoint "$host_dir" "$dst" "$src")" || continue
    fi
    if [[ -f "$src" ]]; then
      if [[ "$mode" == "rw" ]]; then
        echo "Warning: Mount entry '${line}' (from ~/.agent-vm/volumes) requests rw on a file; only directories support rw. Mount the parent directory instead. Skipping." >&2
        continue
      fi
      # File mount: hardlink the source into a per-VM host staging dir so
      # the VM sees only this file (never the source's parent). Lima mounts
      # the staging dir; a bind mount inside the VM (applied after boot)
      # exposes the file at its final destination.
      local filename=""
      filename="$(basename "$src")"
      local file_staging_dir="$AGENT_VM_STATE_DIR/file-mounts/${vm_name}/${staging_idx}"
      local host_staging="${file_staging_dir}/${filename}"
      if ! _agent_vm_stage_file "$src" "$host_staging"; then
        echo "Warning: Failed to stage '${src}', skipping." >&2
        rm -rf "$file_staging_dir"
        continue
      fi
      local staging_mount="/tmp/.agent-vm-file-mounts/${staging_idx}"
      local bind_dst="${dst:-${src}}"
      file_mount_entries+=("${src}|${host_staging}|${staging_mount}/${filename}|${bind_dst}")
      mounts_json+=", {\"location\": \"$(_agent_vm_host_path "$file_staging_dir")\", \"mountPoint\": \"${staging_mount}\", \"writable\": false${sshfs_ro}}"
      staging_idx=$((staging_idx + 1))
      continue
    fi
    if [[ ! -d "$src" ]]; then
      echo "Warning: Mount path '${src}' (from ~/.agent-vm/volumes) is not a regular file or directory, skipping." >&2
      continue
    fi
    local writable="false"
    if [[ "$mode" == "rw" ]]; then
      if [[ "$project_writable" == "true" ]]; then
        writable="true"
      else
        echo "Note: --readonly: '${src}' (rw in ~/.agent-vm/volumes) is mounted read-only too." >&2
      fi
    fi
    sshfs="$sshfs_ro"
    [[ "$writable" != true ]] || sshfs="$sshfs_rw"
    mounts_json+=", {\"location\": \"$(_agent_vm_host_path "$src")\", \"mountPoint\": \"${dst:-$src}\", \"writable\": ${writable}${sshfs}}"
  done <<< "$(_agent_vm_volume_entries "$host_dir")"
  mounts_json+="]"

  rm -f "$file_mounts_cache"
  if [[ ${#file_mount_entries[@]} -gt 0 ]]; then
    printf '%s\n' "${file_mount_entries[@]}" >| "$file_mounts_cache"
  fi

  printf '%s' "$mounts_json"
}

# The mounts JSON last applied to <vm>, kept so --readonly can tell whether
# any share is still writable: the guest cannot be asked, since after a mode
# change it still believes the old one (see _agent_vm_push_env_and_probe).
# A record that could not be written goes: an old one would keep claiming the
# protection or the mode the VM had before (a protected .git, read-only
# shares), and the next start would trust it. With none, it rebuilds them.
_agent_vm_record_mounts() {
  local record
  record="$(_agent_vm_mounts_record "$1")"
  mkdir -p "$AGENT_VM_STATE_DIR" 2>/dev/null && printf '%s\n' "$2" >| "$record" && return 0
  rm -f "$record"
  echo "Error: could not record the shares of VM '$1' in $record." >&2
  return 1
}

# Where that record is kept for <vm>.
_agent_vm_mounts_record() {
  printf '%s\n' "$AGENT_VM_STATE_DIR/.agent-vm-mounts-$1"
}

# 0 when <vm>'s record holds the text <s>. A missing record holds nothing.
_agent_vm_mounts_record_has() {
  local record
  record="$(_agent_vm_mounts_record "$1")"
  [[ -f "$record" ]] && grep -qF -- "$2" "$record"
}

# 0 when <vm> is recorded with no writable share at all. A missing record
# counts as "not known to be read-only".
_agent_vm_mounts_all_readonly() {
  [[ -f "$(_agent_vm_mounts_record "$1")" ]] && ! _agent_vm_mounts_record_has "$1" '"writable": true'
}

# 0 when <vm> is recorded with every .git read-only (see
# _agent_vm_build_mounts_json). A missing record counts as "not protected".
_agent_vm_mounts_protect_git() {
  _agent_vm_mounts_record_has "$1" '"readonlyNames"'
}

# 0 when <vm> is recorded with readonlyNames <names> (a JSON array, as
# _agent_vm_readonly_names prints it).
_agent_vm_mounts_have_readonly_names() {
  _agent_vm_mounts_record_has "$1" "\"readonlyNames\": $2"
}

# Lima's config for <vm>, in one call: its VM type, mount type and mounts (as
# JSON), space-separated. Asked of Lima, not of agent-vm's record: Lima adds
# the mounts of its _config/default.yaml and override.yaml to every VM, and
# its config is what a running VM booted with (Lima refuses to edit a
# running one).
_agent_vm_live_config() {
  limactl list --format '{{.VMType}} {{.Config.MountType}} {{json .Config.Mounts}}' "$1" 2>/dev/null
}

# Sets the caller's live_vmtype, live_mtype and live_json from <live> (see
# _agent_vm_live_config). The mount type may be missing; the JSON, null or an
# array, is last. Fails when <live> holds no JSON: Lima did not answer.
_agent_vm_live_fields() {
  local rest
  live_vmtype="${1%% *}" live_mtype="" live_json=""
  [[ "$1" == *" "* ]] || return 1
  rest="${1#* }"
  rest="${rest# }"
  case "$rest" in
    null*|"["*) ;;
    *) live_mtype="${rest%% *}"; rest="${rest#"$live_mtype"}"; rest="${rest# }" ;;
  esac
  case "$rest" in
    null|"["*) live_json="$rest" ;;
    *) return 1 ;;
  esac
}

# Fails, printing why, unless the config <live> (see _agent_vm_live_config)
# gives every share the builtin SFTP server and the read-only names <names>
# (a JSON array; any names when empty), served by reverse-sshfs. A VM without
# a share passes. A share without them lets the VM write the .git it holds.
_agent_vm_live_shares_why() {
  local live_vmtype live_mtype live_json want='"readonlyNames":['
  if ! _agent_vm_live_fields "$1"; then
    echo "Lima could not be asked for the VM's config"
    return 1
  fi
  # As Lima prints it: no space after the commas (a name may hold a space).
  [[ -z "${2:-}" ]] || want="\"readonlyNames\":${2//\", \"/\",\"}"
  # One record per share: each mount object starts with its location, and no
  # name can hold a quote.
  printf '%s\n' "$live_json" | awk -v want="$want" -v mtype="${live_mtype:-unset}" '
    BEGIN { RS = "[{]\"location\":" }
    NR > 1 {
      n++
      if (index($0, "\"sftpDriver\":\"builtin\"") == 0 || index($0, want) == 0) {
        loc = $0; sub(/^"/, "", loc); sub(/".*/, "", loc)
        print "the share of " loc " lacks the read-only names, or the builtin SFTP server"
        bad = 1
        exit
      }
    }
    END {
      if (!bad && n > 0 && mtype != "reverse-sshfs") {
        print "its mount type is " mtype ", and the read-only names need reverse-sshfs"
        bad = 1
      }
      exit bad
    }'
}

# Fails, printing why, unless .git is read-only for <vm> now: agent-vm gave
# its shares the read-only names (the record), the Lima installed serves
# them, Lima's config (<live> when given, see _agent_vm_live_config) gives
# them to every share (see _agent_vm_live_shares_why), and the limactl
# serving it, when it runs, is that Lima (see _agent_vm_hostagent_is_limactl).
_agent_vm_protection_why() {
  local why live
  if [[ $# -ge 2 ]]; then live="$2"; else live="$(_agent_vm_live_config "$1")"; fi
  if ! _agent_vm_mounts_protect_git "$1"; then
    echo "agent-vm did not give its shares the read-only names"
    return 1
  fi
  if ! _agent_vm_lima_protects_git; then
    echo "the Lima installed cannot keep .git read-only"
    return 1
  fi
  why="$(_agent_vm_live_shares_why "$live")" || { echo "$why"; return 1; }
  if _agent_vm_running "$1" && ! _agent_vm_hostagent_is_limactl "$1"; then
    echo "it was started by another limactl than $(_agent_vm_limactl_path)"
    return 1
  fi
}

# 1 when the running <vm> is served by another limactl build than the one on
# PATH, which agent-vm checked: a stock Lima started it (by hand, at login,
# or from a shell with another PATH) and ignores the read-only names, or an
# older build since replaced. 0 when it is the same file, or the same
# version, or when that cannot be told (Windows, no pid file, no way to see
# the running binary): never a reason to stop on its own.
# The running binary is asked of the kernel: /proc on Linux, where it can
# still be run after its file was replaced; lsof on macOS, where ps only
# knows the path it was started by, a Homebrew link that may point elsewhere
# now.
_agent_vm_hostagent_is_limactl() {
  local pid="" exe="" run="" mine
  _agent_vm_on_windows && return 0
  { read -r pid < "$(_agent_vm_lima_home)/$1/ha.pid"; } 2>/dev/null
  [[ "$pid" =~ ^[0-9]+$ ]] || return 0
  if [[ -e "/proc/$pid/exe" ]]; then
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
    run="/proc/$pid/exe"
  elif command -v lsof >/dev/null 2>&1; then
    exe="$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | awk '/^n/ { print substr($0, 2); exit }')"
    run="$exe"
  fi
  [[ "$exe" == /* ]] || return 0
  mine="$(_agent_vm_limactl_path)"
  [[ -n "$mine" ]] || return 0
  [[ "$exe" -ef "$mine" ]] && return 0
  [[ -x "$run" && "$("$run" --version 2>/dev/null)" == "$(limactl --version 2>/dev/null)" ]]
}

# How sshfs caches what the shares serve (see _agent_vm_build_mounts_json):
# writable-off by default, the cache off on the writable shares only; on
# with AGENT_VM_SSHFS_CACHE=1, read from the shell, never from the project.
# On is faster on many files (a repeated `git status` sends about 20 times
# fewer requests to the host), and the VM may then see a file as it was for
# up to 20 seconds, and write that back.
_agent_vm_sshfs_cache_mode() {
  if [[ "${AGENT_VM_SSHFS_CACHE:-}" == 1 ]]; then echo on; else echo writable-off; fi
}

# 0 when <vm>'s shares were given the cache mode they would get now (recorded
# by _agent_vm_apply_shares).
_agent_vm_mounts_sshfs_current() {
  local mode=""
  { read -r mode < "$AGENT_VM_STATE_DIR/.agent-vm-sshfs-cache-$1"; } 2>/dev/null
  [[ "$mode" == "$(_agent_vm_sshfs_cache_mode)" ]]
}

# _agent_vm_push_env_and_probe <vm> <dir> <payload> [<env> [<runtime>]], in
# one round trip:
# - writes ~/.agent-vm.env in the VM (mode 600, sourced by its ~/.zshenv):
#   <payload> (see _agent_vm_env_payload), then the project's <env>, read by
#   the VM, CRs dropped; empty too, so env removed on the host goes. Prints
#   env-ok.
# - prints runtime-found when the project's <runtime> is there.
# - returns whether a write into the project <dir> succeeds: 0 yes, 1 no. A
#   real write, removed at once, not `test -w`: after a mode change the
#   guest's fstab still shows the old one.
# - returns 2 when the share is not mounted (sshfs died, or never mounted),
#   where the VM writes in the bare mount point on its own disk: the guest
#   does not see the file this machine put in <dir> just before (prints
#   share-ok when it does). Not for the caller's scratch VM, which shares
#   nothing: no file is put on this machine then.
_agent_vm_push_env_and_probe() {
  local vm_name="$1" host_dir="$2" payload="$3" token="" out st=0
  if [[ -z "${scratch:-}" ]]; then
    token=".agent-vm-probe.$$.$RANDOM$RANDOM"
    # Never through something already there: set -C refuses it.
    ( set -C; : > "$host_dir/$token" ) 2>/dev/null || token=""
  fi
  out="$({ [ -z "$payload" ] || printf '%s\n' "$payload"; } \
    | limactl shell "$vm_name" sh -c '
        (umask 077 && rm -f "$HOME/.agent-vm.env" && { cat; [ -z "$2" ] || [ ! -f "$2" ] || awk "{ sub(/\r\$/, \"\"); print }" "$2"; } > "$HOME/.agent-vm.env") && echo env-ok
        [ -z "$3" ] || [ ! -f "$3" ] || echo runtime-found
        [ -z "$4" ] || [ ! -f "$1/$4" ] || echo share-ok
        p="$1/.agent-vm-write-probe.$$"; touch "$p" 2>/dev/null || exit 1; rm -f "$p"' \
      sh "$host_dir" "${4:-}" "${5:-}" "$token" 2>/dev/null)" || st=$?
  [[ -z "$token" ]] || rm -f "$host_dir/$token"
  printf '%s\n' "$out"
  # The guest answered, but without the share.
  [[ -z "$token" || "$out" != *env-ok* || "$out" == *share-ok* ]] || return 2
  [[ "$st" == 0 ]]
}

# Are <vm>'s shares ones whose read-only flag is enforced outside the guest?
# Answered on the host, from the VM type and mount type Lima has for the VM,
# never by asking the guest: a compromised one would say whatever passes.
# agent-vm only changes the mount type of a stopped VM, so the config is what
# the VM runs with. 9p is enforced by QEMU (`readonly=on` on -virtfs).
# virtiofs is enforced on vz only, by Virtualization.framework: under QEMU,
# virtiofsd has no read-only mode and Lima passes none
# (virtio-fs/virtiofsd#97), so the flag only reaches the guest's fstab.
# reverse-sshfs is enforced only when served by the builtin SFTP server of a
# Lima with readonlyNames, as _agent_vm_protection_why tells. Otherwise it
# only gets `-o ro` inside the guest, where root can remount it rw, and the
# SFTP server is not confined to the shares. Returns 0 (enforced), 1 (not
# enforced), or 2 (could not tell).
_agent_vm_mount_is_host_enforced() {
  local live vmtype mtype live_vmtype live_mtype live_json
  live="$(_agent_vm_live_config "$1")" || return 2
  _agent_vm_live_fields "$live" || return 2
  vmtype="$live_vmtype"
  mtype="$live_mtype"
  case "$mtype" in
    ""|default|"<nil>"|"<no value>") mtype="$(_agent_vm_default_mount_type "$1" "$vmtype")" ;;
  esac
  case "$vmtype $mtype" in
    "vz virtiofs"|"qemu 9p") return 0 ;;
    "qemu virtiofs") return 1 ;;
    ?*" reverse-sshfs")
      _agent_vm_protection_why "$1" "$live" >/dev/null && return 0
      return 1 ;;
    *) return 2 ;;
  esac
}

# The mount type Lima gives <vm> (of VM type <vmtype>) when its config leaves
# it unset, as agent-vm does without the .git protection: the one Lima's
# _config/override.yaml or default.yaml sets, if any, else the one its driver
# picks at start (and `limactl list` shows unset): virtiofs on vz, 9p on QEMU
# except on Windows or for a VM made by a Lima before 1.0 (no lima-version
# file before 0.20). Nothing for another.
_agent_vm_default_mount_type() {
  local ver f t
  for f in override default; do
    t="$(awk '/^mountType:/ { v = $2; gsub(/["\047]/, "", v); print v; exit }' \
      "$(_agent_vm_lima_home)/_config/$f.yaml" 2>/dev/null)"
    if [[ -n "$t" ]]; then
      echo "$t"
      return 0
    fi
  done
  case "$2" in
    vz) echo virtiofs ;;
    qemu)
      ver="$(cat "$(_agent_vm_lima_home)/$1/lima-version" 2>/dev/null)"
      if _agent_vm_on_windows || [[ -z "$ver" ]] || ! _agent_vm_ver_ge "$ver" 1.0.0; then
        echo reverse-sshfs
      else
        echo 9p
      fi ;;
  esac
}

# 0 when <vm>, without the .git protection, would share through reverse-sshfs
# served by a Lima without readonlyNames. Lima's mount documentation says a
# compromised guest may then reach host paths outside the shares, through the
# SFTP server: not only .git is at stake, the rest of the disk is. On Windows
# always; elsewhere for a QEMU VM made by a Lima before 1.0. A VM not made yet
# is asked about the base template it is cloned from.
_agent_vm_unprotected_mount_is_sshfs() {
  local vm="$1" vmtype
  _agent_vm_on_windows && return 0
  _agent_vm_exists "$vm" || vm="$AGENT_VM_TEMPLATE"
  vmtype="$(limactl list --format '{{.VMType}}' "$vm" 2>/dev/null)" || return 1
  [[ "$(_agent_vm_default_mount_type "$vm" "${vmtype%% *}")" == reverse-sshfs ]]
}
