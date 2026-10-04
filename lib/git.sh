# --- .git protection ------------------------------------------------------------
# Git on the host runs what a repository's .git/config and hooks name
# (core.fsmonitor on every `git status`, hooks on commit), and editors and
# shell prompts run git on their own. A VM able to write a .git in a shared
# folder could therefore run commands on the host.
#
# Lima's `sshfs.readonlyNames` makes every path with a `.git` component
# read-only for the guest, at any depth, while the rest of the share stays
# writable. Lima's builtin SFTP server enforces it on the host, so root in the
# guest cannot lift it. It needs mountType reverse-sshfs and the builtin driver
# on every mount.
#
# Upstream Lima does not have it yet (lima-vm/lima#5529). Until it does, a
# Lima build that has it: the Homebrew formula, or the tag it is built from.
AGENT_VM_LIMA_FORMULA="sylvinus/tap/lima-sylvinus"
AGENT_VM_LIMA_FORK_TAG="v2.3.0-sylvinus.2"
# The Windows zips of that tag, in SHA256SUMS format. The download is checked
# against these, not against the SHA256SUMS of the release, which whoever can
# replace the zips can replace too. Updated with the tag.
AGENT_VM_LIMA_FORK_SHA256="053f3479b397628b79fe46b0268a50a7f1fc51073691d7d8bce78c9be2ae2787  lima-2.3.0-sylvinus.2-Windows-AMD64.zip
a0828aa4518e21c9519d341be9f32adf07cbeb74a3f8beadaa2f350c45b5933b  lima-additional-guestagents-2.3.0-sylvinus.2-Windows-AMD64.zip
1cb2d94a9a5f38b2f38f9c14715d850a861a9623b9a7f7ae7b0f6431b75aaa81  lima-2.3.0-sylvinus.2-Windows-ARM64.zip
1ae0b7b054191f4197898bd59697ee99350d3b7e95b895c1b0ec061c7ea87e7f  lima-additional-guestagents-2.3.0-sylvinus.2-Windows-ARM64.zip"
AGENT_VM_LIMA_ISSUE="https://github.com/lima-vm/lima/issues/5529"

# Does this Lima enforce sshfs.readonlyNames? 0 yes, 1 no, 2 cannot tell.
# Stock Lima accepts the field and ignores it, with a mere warning, so support
# is probed, never assumed: `limactl validate` on a config giving it a name
# with a slash, which a Lima that knows the field rejects, naming it, whatever
# mount type Lima's _config/override.yaml imposes (with another than
# reverse-sshfs, it rejects that too). One that does not know it warns about
# an "unknown field". Any other answer (no limactl, a failure that names
# neither, a Lima that accepts the file without a word) is "cannot tell",
# never "no": callers must not drop the protection of a VM on an answer they
# could not read.
#
# Not cached: agent-vm is also a shell function, where a cached answer would
# outlive a Lima upgrade.
_agent_vm_lima_protects_git() {
  local dir out accepted=""
  dir="$(mktemp -d 2>/dev/null)" || return 2
  printf 'images: [{location: "/"}]\nmountType: reverse-sshfs\nmounts: [{location: "%s", sshfs: {sftpDriver: builtin, readonlyNames: [a/b]}}]\n' \
    "$(_agent_vm_host_path "$dir")" > "$dir/probe.yaml"
  out="$(limactl validate "$(_agent_vm_host_path "$dir/probe.yaml")" 2>&1)" && accepted=1
  rm -rf "$dir"
  if [[ "$out" == *"unknown field"* && "$out" == *readonlyNames* ]]; then
    return 1
  elif [[ -z "$accepted" && "$out" == *readonlyNames* ]]; then
    return 0
  fi
  return 2
}

# The `limactl edit --set` expression applying a mounts JSON, and the mount
# type that goes with it. With every .git read-only ($2 = 1): reverse-sshfs,
# which readonlyNames needs. Without: Lima's default, and not a reverse-sshfs
# left over from a Lima that had readonlyNames: on a Lima without it, a
# compromised guest can reach host paths outside the shares through the SFTP
# server (Lima's mount documentation says so for both drivers).
_agent_vm_mounts_expr() {
  if [[ "${2:-}" == 1 ]]; then
    printf '.mountType = "reverse-sshfs" | .mounts = %s' "$1"
  else
    printf 'del(.mountType) | .mounts = %s' "$1"
  fi
}

# The names readonlyNames always lists, one per line. .hg: Mercurial runs the
# hooks of .hg/hgrc in a repository the user owns, which files written through
# a share are.
_AGENT_VM_BASE_NAMES=$'.git\n.hg'
_agent_vm_base_readonly_names() {
  printf '%s\n' "$_AGENT_VM_BASE_NAMES"
}

# 0 when the relative path <rel> goes through one of <names> (one per line;
# the names above by default), matched as the SFTP server does: per
# component, whatever the case.
_agent_vm_under_readonly_name() {
  local rest="$1/" names=$'\n'"${2:-$_AGENT_VM_BASE_NAMES}"$'\n' c st=1 set_nocase=""
  shopt -q nocasematch || { shopt -s nocasematch; set_nocase=1; }
  while [[ -n "$rest" ]]; do
    c="${rest%%/*}"
    rest="${rest#*/}"
    if [[ -n "$c" && "$names" == *$'\n'"$c"$'\n'* ]]; then
      st=0
      break
    fi
  done
  [[ -z "$set_nocase" ]] || shopt -u nocasematch
  return "$st"
}

# 0 on the hosts whose file systems ignore case by default: macOS, Windows.
# A caller asking many times sets _agent_vm_nocase_memo to 1 or 0 first.
_agent_vm_fs_nocase() {
  case "${_agent_vm_nocase_memo:-}" in
    1) return 0 ;;
    0) return 1 ;;
  esac
  [[ "$(uname -s 2>/dev/null)" == Darwin ]] || _agent_vm_on_windows
}

# <s> lowercased on those hosts, as is elsewhere: paths compared as the file
# system does.
_agent_vm_fold() {
  if _agent_vm_fs_nocase; then
    printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'
  else
    printf '%s\n' "$1"
  fi
}

# <path> relative to <dir>, "." for <dir> itself; fails when it is not inside.
# Compared whatever the case where the file system ignores it, so a path
# spelled with other capitals is still found inside.
_agent_vm_rel_in() {
  local target="${1%/}" dir="${2%/}" st=1 set_nocase=""
  if _agent_vm_fs_nocase && ! shopt -q nocasematch; then
    shopt -s nocasematch
    set_nocase=1
  fi
  if [[ "$target" == "$dir" ]]; then
    printf '.\n'
    st=0
  elif [[ -n "$dir" && "$target" == "$dir/"* ]]; then
    printf '%s\n' "${target:$(( ${#dir} + 1 ))}"
    st=0
  fi
  [[ -z "$set_nocase" ]] || shopt -u nocasematch
  return "$st"
}

# <dir> as git spells it: the physical path, C:/... on Windows.
_agent_vm_git_spelling() {
  local p
  p="$(CDPATH= cd -P -- "$1" 2>/dev/null && pwd)" || return 1
  _agent_vm_host_path "$p"
}

# <path> made absolute against <base> (both in git's spelling), `.` and `..`
# resolved in the text.
_agent_vm_git_abs() {
  case "$1" in
    /*) _agent_vm_path_join / "$1" ;;
    [A-Za-z]:/*) _agent_vm_path_join "${1%%/*}" "${1#*/}" ;;
    *) _agent_vm_path_join "$2" "$1" ;;
  esac
}

# --- what git on this machine runs from the shares -----------------------------
# The VM can write the project and the writable volumes. git on this machine
# runs hooks, and commands its config names, from paths anywhere: in the
# repository's own share, in another share (core.hooksPath into a volume), or
# from git's own config kept in one. Each path is followed through every
# symlink on the way, and checked against every share.

# The folders the VM can write, one per line, in git's spelling (symlinks
# resolved): the project <dir> first, then its writable volumes (see
# _agent_vm_rw_volume_dirs), each once.
_agent_vm_writable_shares() {
  local d
  { printf '%s\n' "$1"; _agent_vm_rw_volume_dirs "$1"; } | while IFS= read -r d; do
    [[ -z "$d" ]] || _agent_vm_git_spelling "$d"
  done | awk '!seen[$0]++'
}

# Sets the caller's hit_share and hit_rel to the deepest of the caller's
# shares (one per line, in git's spelling) holding <path>, and <path>
# relative to it ("." for the share itself). Fails when none does. No
# subshell: it runs for every path a scan looks at.
_agent_vm_in_share() {
  local t="${1%/}" s d r set_nocase=""
  hit_share="" hit_rel=""
  if _agent_vm_fs_nocase && ! shopt -q nocasematch; then
    shopt -s nocasematch
    set_nocase=1
  fi
  while IFS= read -r s; do
    d="${s%/}"
    [[ -n "$d" ]] || continue
    if [[ "$t" == "$d" ]]; then
      r=.
    elif [[ "$t" == "$d/"* ]]; then
      r="${t:$(( ${#d} + 1 ))}"
    else
      continue
    fi
    if [[ ${#d} -gt ${#hit_share} ]]; then
      hit_share="$d"
      hit_rel="$r"
    fi
  done <<< "$shares"
  [[ -z "$set_nocase" ]] || shopt -u nocasematch
  [[ -n "$hit_share" ]]
}

# Every path the file system goes through to reach <path> (absolute, in
# git's spelling), one per line: <path>, the same with its folder's symlinks
# resolved, then the same again for the target of each symlink on the way,
# up to 40 links, whether the last one exists or not. A VM able to write any
# of them chooses what is found there.
_agent_vm_path_hops() {
  local p="$1" d n=0 t
  while :; do
    printf '%s\n' "$p"
    d="${p%/*}"
    if d="$(_agent_vm_git_spelling "${d:-/}" 2>/dev/null)"; then
      d="${d%/}/${p##*/}"
      if [[ "$d" != "$p" ]]; then
        p="$d"
        printf '%s\n' "$p"
      fi
    fi
    [[ -L "$p" ]] || return 0
    n=$((n + 1))
    [[ "$n" -le 40 ]] || return 0
    t="$(readlink "$p")" || return 0
    [[ "$t" != /* ]] || t="$(_agent_vm_host_path "$t")"
    p="$(_agent_vm_git_abs "$t" "${p%/*}")"
  done
}

# git, for the repository <at> of kind <kind>: W a work tree, B a bare
# repository (named explicitly, as safe.bareRepository=explicit allows), G
# none, for git's own global and system config.
_agent_vm_git_at() {
  local kind="$1" at="$2"
  shift 2
  case "$kind" in
    W) _agent_vm_git_untrusted -C "$at" "$@" ;;
    B) _agent_vm_git_untrusted --git-dir="$at" "$@" ;;
    *) _agent_vm_git_untrusted -C / "$@" ;;
  esac
}

# The repositories git on this machine finds in the share <dir> (git's
# spelling), one per line, the kind before a tab (see _agent_vm_git_at): the
# one holding <dir>, then work trees and bare repositories up to two levels
# below it (node_modules skipped), 50 at most. X and <dir> when there are
# more: those are not checked.
_agent_vm_share_repos() {
  local dir="$1" g n=0
  _agent_vm_git_untrusted -C "$dir" rev-parse --git-dir >/dev/null 2>&1 && printf 'W\t%s\n' "$dir"
  while IFS= read -r g; do
    case "$g" in
      */.git) g="${g%/.git}" ;;
      */objects)
        g="${g%/objects}"
        [[ -f "$g/HEAD" && -d "$g/refs" ]] || continue ;;
      *) continue ;;
    esac
    n=$((n + 1))
    if [[ "$n" -gt 50 ]]; then
      printf 'X\t%s\n' "$dir"
      break
    fi
    if [[ -e "$g/.git" ]]; then printf 'W\t%s\n' "$g"; else printf 'B\t%s\n' "$g"; fi
  done <<< "$(find "$dir/" -mindepth 2 -maxdepth 3 \( -name node_modules -prune \) \
                -o \( -name .git -print -prune \) -o \( -name objects -type d -print -prune \) 2>/dev/null \
              | sed 's#//*#/#g')"
}

# The hooks folder of the repository <at> of kind <kind>, absolute, in git's
# spelling, as git names it: symlinks not resolved. For G, the absolute
# core.hooksPath git's own config sets for every repository. Fails when there
# is none, or git cannot tell. `--git-path` without --path-format (git 2.31)
# answers relative to where git runs.
#
# Two lines: the top of the work tree (empty but for W), then the folder.
_agent_vm_scan_hooks_dir() {
  local hooks base=/ top=""
  case "$1" in
    G)
      hooks="$(_agent_vm_git_at G / config --get core.hooksPath 2>/dev/null)" || return 1
      [[ "$hooks" != "~/"* ]] || hooks="$home/${hooks#\~/}"
      [[ "$hooks" == /* || "$hooks" == [A-Za-z]:/* ]] || return 1 ;;
    W)
      hooks="$(_agent_vm_git_at W "$2" rev-parse --show-toplevel --git-path hooks 2>/dev/null)" || return 1
      [[ "$hooks" == *$'\n'* ]] || return 1
      top="${hooks%%$'\n'*}"
      hooks="${hooks#*$'\n'}"
      base="$(_agent_vm_git_spelling "$2")" || return 1 ;;
    *)
      hooks="$(_agent_vm_git_at "$1" "$2" rev-parse --git-path hooks 2>/dev/null)" || return 1 ;;
  esac
  [[ -n "$hooks" && "$hooks" != *[$'\n\t']* && "$top" != *$'\t'* ]] || return 1
  printf '%s\n' "$top"
  _agent_vm_git_abs "$hooks" "$base"
}

# 0 when one of the paths the file system goes through to reach <path> (see
# _agent_vm_path_hops) is in one of the caller's shares, outside the caller's
# names: the VM can choose what is found there. Sets the caller's shown to
# that path, relative to the project when it is there.
_agent_vm_scan_hit() {
  local h hit_share hit_rel
  [[ -n "$1" ]] || return 1
  while IFS= read -r h; do
    [[ -n "$h" ]] && _agent_vm_in_share "$h" || continue
    _agent_vm_under_readonly_name "$hit_rel" "$names" && continue
    shown="$h"
    [[ "$hit_share" != "$proj" ]] || shown="$hit_rel"
    return 0
  done <<< "$(_agent_vm_path_hops "$1")"
  return 1
}

# A risk line of the scan: <text>, its control characters made visible.
_agent_vm_scan_risk() {
  local t="$1"
  printf 'R\t%s\n' "${t//[[:cntrl:]]/?}"
}

# The risk lines of the config of the repository <at> of kind <kind>, whose
# work tree is <top> (see _agent_vm_git_at): its own config, or git's global
# and system config for G. Config files in a share, included ones whether
# they exist yet or not (git skips a missing one, and the VM can create it).
# Settings whose command a share holds: a path in their value, relative to
# the top of the repository, where git runs most of them (git's own config
# has none to take them from). awk sorts the config first, so the shell only
# sees each file once and the settings that hold a command (section and key
# names lowercased, as `git config --list` prints them) with a path in their
# value: a start runs this, and a fork per line would show.
_agent_vm_scan_config() {
  local kind="$1" at="$2" cmd_base="$3" base=/ scope=--local k a b c w shown
  case "$kind" in
    W) base="$(_agent_vm_git_spelling "$at")" || return 0 ;;
    B) cmd_base="$at" ;;
    *) scope="" ;;
  esac
  _agent_vm_git_at "$kind" "$at" config --list ${scope:+"$scope"} --show-origin --includes 2>/dev/null \
    | awk -F '\t' '
        {
          origin = $1; kv = substr($0, length($1) + 2); f = ""
          if (origin ~ /^file:/) { f = substr(origin, 6); gsub(/^"|"$/, "", f) }
          if (f != "" && !(f in seen)) { seen[f] = 1; print "O\t" f }
          key = kv; sub(/=.*/, "", key); val = substr(kv, length(key) + 2); lk = tolower(key)
          if (lk == "include.path" || lk ~ /^includeif\..*\.path$/) {
            if (f != "") print "I\t" f "\t" val
            next
          }
          if (lk !~ /^(core\.(fsmonitor|sshcommand|editor|pager|askpass|gitproxy|alternaterefscommand)|sequence\.editor|gpg\.program|gpg\..*\.program|diff\.external|diff\..*\.(command|textconv)|(difftool|mergetool|browser|man)\..*\.cmd|merge\..*\.driver|filter\..*\.(clean|smudge|process)|credential\.helper|credential\..*\.helper|pager\..*|alias\..*|interactive\.difffilter|uploadpack\.packobjectshook|web\.browser)$/) next
          if (lk ~ /^alias\./ && val !~ /^!/) next
          if (val ~ /\//) print "K\t" f "\t" key "\t" val
        }' \
    | while IFS=$'\t' read -r k a b c; do
        case "$k" in
          O)
            _agent_vm_scan_hit "$(_agent_vm_git_abs "$a" "$base")" && _agent_vm_scan_risk "config file $shown" ;;
          I)
            # Relative to the file holding it, as git takes it.
            [[ "$b" != "~/"* ]] || b="$home/${b#\~/}"
            a="$(_agent_vm_git_abs "$a" "$base")"
            _agent_vm_scan_hit "$(_agent_vm_git_abs "$b" "${a%/*}")" && _agent_vm_scan_risk "config file $shown" ;;
          K)
            # Word by word, through awk: an unquoted expansion would glob them.
            printf '%s\n' "${c#!}" | awk '{ for (i = 1; i <= NF; i++) print $i }' \
              | while IFS= read -r w; do
                  w="${w#[\"\']}"; w="${w%[\"\']}"
                  # Not an option, an assignment or a URL: a path.
                  [[ "$w" == */* && "$w" != -* && "$w" != *=* && "$w" != *://* ]] || continue
                  [[ "$w" != "~/"* ]] || w="$home/${w#\~/}"
                  [[ "$w" == /* || "$w" == [A-Za-z]:/* || -n "$cmd_base" ]] || continue
                  _agent_vm_scan_hit "$(_agent_vm_git_abs "$w" "$cmd_base")" || continue
                  _agent_vm_scan_risk "$b = $c"
                  break
                done ;;
        esac
      done
}

# What git on this machine runs, or reads, from the folders the VM can write
# (see _agent_vm_writable_shares) for the project <dir>: the repositories of
# each share and git's own config. One line each, its kind first, then
# tab-separated:
# - H: a hooks folder, or a link on the way to it, in a share and outside the
#   names always listed. Where it is (relative to the project when it is
#   there, else absolute), then what names it (see _agent_vm_hooks_name):
#   relative to the top of its repository when that is in the share
#   (lib/x/.githooks is .githooks), else to the share; "." for a share
#   itself, empty for a name no share can carry.
# - R: a risk to accept, as text: a config file in a share, a setting whose
#   command is in one, a hook linked to a file in one, a share with more
#   repositories than are checked.
# What a name keeps read-only is no risk: the names always listed, and those
# of the hooks folders found here. Each line once.
_agent_vm_git_scan() {
  command -v git >/dev/null 2>&1 || return 0
  _agent_vm_git_scan_lines "$1" | awk '!seen[$0]++'
}

_agent_vm_git_scan_lines() {
  local shares proj home s kind at i n=0 hooks hp top h f t in_repo name shown
  local hit_share hit_rel top_share top_rel names="$_AGENT_VM_BASE_NAMES"
  local _agent_vm_windows_memo=0 _agent_vm_nocase_memo=0 kinds=() ats=() hookss=() tops=()
  _agent_vm_on_windows && _agent_vm_windows_memo=1
  _agent_vm_fs_nocase && _agent_vm_nocase_memo=1
  shares="$(_agent_vm_writable_shares "$1")"
  [[ -n "$shares" ]] || return 0
  proj="${shares%%$'\n'*}"
  home="$(_agent_vm_host_path "$HOME")"
  while IFS=$'\t' read -r kind at; do
    case "$kind" in
      X)
        shown="$at"
        _agent_vm_in_share "$at" && [[ "$hit_share" == "$proj" ]] && shown="$hit_rel"
        _agent_vm_scan_risk "more than 50 repositories in $shown: those after the 50th are not checked" ;;
      W|B|G) kinds[n]="$kind"; ats[n]="$at"; n=$((n + 1)) ;;
    esac
  done <<< "$(while IFS= read -r s; do _agent_vm_share_repos "$s"; done <<< "$shares"
              printf 'G\t/\n')"
  # The hooks folders first: their names keep what is under them read-only.
  for ((i = 0; i < n; i++)); do
    top="" hooks=""
    if h="$(_agent_vm_scan_hooks_dir "${kinds[i]}" "${ats[i]}")"; then
      top="${h%%$'\n'*}"
      hooks="${h#*$'\n'}"
    elif [[ "${kinds[i]}" == W ]]; then
      top="$(_agent_vm_git_at W "${ats[i]}" rev-parse --show-toplevel 2>/dev/null)" || top=""
    fi
    hookss[i]="$hooks"
    tops[i]="$top"
    [[ -n "$hooks" ]] || continue
    top_share="" top_rel=""
    if [[ -n "$top" ]] && _agent_vm_in_share "$top"; then
      top_share="$hit_share" top_rel="$hit_rel"
    fi
    while IFS= read -r h; do
      [[ -n "$h" ]] && _agent_vm_in_share "$h" || continue
      [[ "$hit_rel" == . ]] || ! _agent_vm_under_readonly_name "$hit_rel" || continue
      in_repo="$hit_rel"
      if [[ "$hit_share" == "$top_share" && "$top_rel" != . ]]; then
        in_repo="$(_agent_vm_rel_in "$h" "$top")" || in_repo="$hit_rel"
      fi
      [[ "$in_repo" != *[[:cntrl:]]* ]] || in_repo=""
      shown="$h"
      [[ "$hit_share" != "$proj" ]] || shown="$hit_rel"
      printf 'H\t%s\t%s\n' "${shown//[[:cntrl:]]/?}" "$in_repo"
      if name="$(_agent_vm_hooks_name "$in_repo")"; then
        names="$names"$'\n'"$name"
      fi
    done <<< "$(_agent_vm_path_hops "$hooks")"
  done
  for ((i = 0; i < n; i++)); do
    _agent_vm_scan_config "${kinds[i]}" "${ats[i]}" "${tops[i]}"
    # A hook linked to a file a share holds: git runs that file, which may
    # be outside every name.
    hooks="${hookss[i]}"
    [[ -n "$hooks" ]] && hp="$(_agent_vm_git_spelling "$hooks")" || continue
    for f in "$hp"/*; do
      [[ -L "$f" && "$f" != *.sample ]] || continue
      t="$(readlink "$f")" || continue
      [[ "$t" != /* ]] || t="$(_agent_vm_host_path "$t")"
      _agent_vm_scan_hit "$(_agent_vm_git_abs "$t" "$hp")" && _agent_vm_scan_risk "hook ${f##*/} runs $shown"
    done
  done
}

# The lines of kind <kind> (H or R) of a scan (see _agent_vm_git_scan), the
# kind dropped.
_agent_vm_scan_part() {
  printf '%s\n' "$2" | awk -F '\t' -v k="$1" '$1 == k { print substr($0, length(k) + 2) }'
}

# The hooks folders of the project <dir>'s shares, as the H lines of the
# scan: where, then what names it, tab-separated.
_agent_vm_share_hooks() {
  _agent_vm_scan_part H "$(_agent_vm_git_scan "$1")"
}

# The risks to accept for the project <dir>'s shares, as the R lines of the
# scan.
_agent_vm_share_config_risks() {
  _agent_vm_scan_part R "$(_agent_vm_git_scan "$1")"
}

# The name that keeps the hooks folder <rel> read-only: its first component,
# which covers the folder and whatever it calls next to it (husky's hooks call
# .husky/<hook>). Fails for the project itself, and for a name the mounts JSON
# cannot carry.
_agent_vm_hooks_name() {
  local name="${1%%/*}"
  [[ "$1" != . && -n "$name" && "$name" != *[\"\\]* && "$name" != *[[:cntrl:]]* ]] || return 1
  printf '%s\n' "$name"
}

# The readonlyNames JSON array: the names always listed, then "$@", each once.
_agent_vm_names_json() {
  local n out="" seen=$'\n'
  for n in $(_agent_vm_base_readonly_names) "$@"; do
    [[ "$seen" == *$'\n'"$n"$'\n'* ]] && continue
    seen="$seen$n"$'\n'
    out="${out:+$out, }\"$n\""
  done
  printf '[%s]\n' "$out"
}

# The readonlyNames JSON array a start gives the project <dir> unless the user
# declines a name: the names always listed, and those keeping its hooks
# folders read-only. From <scan> (see _agent_vm_git_scan) when given.
_agent_vm_readonly_names() {
  local rel in_repo name names=() scan
  if [[ $# -ge 2 ]]; then scan="$2"; else scan="$(_agent_vm_git_scan "$1")"; fi
  while IFS=$'\t' read -r rel in_repo; do
    [[ -n "$rel" ]] || continue
    name="$(_agent_vm_hooks_name "$in_repo")" && names+=("$name")
  done <<< "$(_agent_vm_scan_part H "$scan")"
  _agent_vm_names_json ${names[@]+"${names[@]}"}
}

# A readonlyNames JSON array as text: [".git", ".hg"] is ".git, .hg".
_agent_vm_names_text() {
  local s="${1#\[}"
  s="${s%\]}"
  printf '%s\n' "${s//\"/}"
}

_agent_vm_hooks_note() {
  echo "Note: git runs hooks from $1 (core.hooksPath): every '$2' in the project is read-only for the VM too."
}

# What a Lima without readonlyNames exposes when the shares are reverse-sshfs
# (see _agent_vm_unprotected_mount_is_sshfs), one paragraph, before
# _agent_vm_git_protection_hint.
_agent_vm_sshfs_exposure_note() {
  echo "Here the shares then use Lima's reverse-sshfs, which this Lima does not confine: root in the VM may reach files outside the shares (Lima's mount documentation says so), your SSH keys and the rest of your disk included, and write the read-only volumes."
  echo ""
}

# Why .git is not protected, and how to install a Lima that does it, on stdout.
# With Homebrew (macOS, or Linux): the formula, which conflicts with brew's own
# lima, hence the unlink. On Windows: the fork's release zips, which `setup`
# offers to download. Without either: a build from source, as the formula
# does it. One paragraph per line: _agent_vm_wrap and _agent_vm_box fit it to
# the screen.
_agent_vm_git_protection_hint() {
  cat <<EOF
An agent could write .git/config or .git/hooks in your projects, and git on this machine would run them, even when your editor or shell prompt calls git.

A Lima build with sshfs.readonlyNames prevents it, until upstream merges it ($AGENT_VM_LIMA_ISSUE):
EOF
  if _agent_vm_on_windows; then
    echo "  agent-vm setup offers the download, or get it by hand:"
    echo "  $(_agent_vm_lima_fork_release) (both Windows zips, verified, on PATH)"
  elif command -v brew >/dev/null 2>&1; then
    echo "  brew unlink lima 2>/dev/null; brew install $AGENT_VM_LIMA_FORMULA"
  else
    echo "  git clone --depth 1 -b $AGENT_VM_LIMA_FORK_TAG https://github.com/sylvinus/lima"
    echo "  cd lima && make native && sudo make install   # needs Go and make"
  fi
}

# The URL of the fork release holding the Windows builds.
_agent_vm_lima_fork_release() {
  printf 'https://github.com/sylvinus/lima/releases/download/%s\n' "$AGENT_VM_LIMA_FORK_TAG"
}

# Windows architecture as the asset names spell it (AMD64/ARM64), from uname.
_agent_vm_lima_fork_arch() {
  case "$(uname -m 2>/dev/null)" in
    x86_64) printf 'AMD64\n' ;;
    aarch64|arm64) printf 'ARM64\n' ;;
    *)
      echo "Error: no Lima fork build for this architecture: $(uname -m 2>/dev/null)" >&2
      return 1 ;;
  esac
}

# The fork release's files for this machine, one per line: both zips, named
# as upstream's `make artifacts-windows` does,
# lima-<tag without v>-Windows-<ARCH>.zip.
_agent_vm_lima_fork_files() {
  local arch tag
  arch="$(_agent_vm_lima_fork_arch)" || return 1
  tag="${AGENT_VM_LIMA_FORK_TAG#v}"
  printf 'lima-%s-Windows-%s.zip\n' "$tag" "$arch"
  printf 'lima-additional-guestagents-%s-Windows-%s.zip\n' "$tag" "$arch"
}

# Every file named in "$@" inside <dir> must match its entry in <sums>, text
# in SHA256SUMS format. Fails closed (an unlisted file, a checksum that cannot
# be computed, a mismatch) naming the culprit, so a half-downloaded Lima never
# lands on PATH.
_agent_vm_sha256_sums_check() {
  local sums="$1" dir="$2" f expected actual
  shift 2
  for f in "$@"; do
    # A leading * marks binary mode (`sha256sum -b`, and Git Bash's default).
    expected="$(printf '%s\n' "$sums" | awk -v f="$f" '{ n = $2; sub(/^\*/, "", n) } n == f { print $1; exit }')"
    if [[ -z "$expected" ]]; then
      echo "Error: no checksum listed for $f." >&2
      return 1
    fi
    actual="$(_agent_vm_sha256 < "$dir/$f" 2>/dev/null | cut -d' ' -f1)"
    if [[ -z "$actual" || "$actual" != "$expected" ]]; then
      echo "Error: checksum mismatch for $f (expected $expected, got ${actual:-unreadable})." >&2
      return 1
    fi
  done
}

# Download and install the fork's Windows build: both zips, verified against
# AGENT_VM_LIMA_FORK_SHA256, then unpacked into a staging dir next to AGENT_VM_LIMA_DIR
# (default ~/.local/share/lima-sylvinus), which takes its place only once
# complete. A failed run leaves the previous install, or none, as it was.
#
# An install of AGENT_VM_LIMA_FORK_TAG is reused. One of another tag (or
# unmarked) is replaced, in the same directory, so the PATH line the user
# already has keeps working. Windows cannot move a directory whose limactl.exe
# is running, which is the case while a VM runs: that is said, and the old
# install stays.
#
# The bin dir goes on PATH for the rest of this shell when it is not there
# already, with the line making it permanent printed alongside: setup needs
# limactl immediately, and the user needs it in the next terminal.
_agent_vm_install_fork_windows() {
  local base dir tmp f bin="" stage old=""
  base="$(_agent_vm_lima_fork_release)"
  dir="${AGENT_VM_LIMA_DIR:-$HOME/.local/share/lima-sylvinus}"
  if [[ -x "$dir/bin/limactl.exe" \
        && "$(cat "$dir/.agent-vm-lima-tag" 2>/dev/null)" == "$AGENT_VM_LIMA_FORK_TAG" ]]; then
    bin="$dir/bin"
    echo "Lima $AGENT_VM_LIMA_FORK_TAG is already installed at $bin."
  else
    if [[ -e "$dir" && ! -x "$dir/bin/limactl.exe" ]]; then
      echo "Error: $dir exists and is not a Lima install: move it, or set AGENT_VM_LIMA_DIR." >&2
      return 1
    fi
    command -v curl >/dev/null 2>&1 \
      || { echo "Error: curl is required to download Lima." >&2; return 1; }
    local files
    files="$(_agent_vm_lima_fork_files)" || return 1
    mkdir -p "$(dirname "$dir")" || return 1
    tmp="$(mktemp -d 2>/dev/null)" || return 1
    # The || keeps the last line: command substitution strips its newline.
    while IFS= read -r f || [[ -n "$f" ]]; do
      [[ -n "$f" ]] || continue
      echo "Downloading $f..."
      if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 \
           -o "$tmp/$f" "$base/$f"; then
        echo "Error: could not download $base/$f." >&2
        rm -rf "$tmp"
        return 1
      fi
      if ! _agent_vm_sha256_sums_check "$AGENT_VM_LIMA_FORK_SHA256" "$tmp" "$f"; then
        rm -rf "$tmp"
        return 1
      fi
    done <<< "$files"
    stage="$dir.new.$$"
    rm -rf "$stage"
    mkdir -p "$stage" || { rm -rf "$tmp"; return 1; }
    while IFS= read -r f || [[ -n "$f" ]]; do
      [[ -n "$f" ]] || continue
      if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$tmp/$f" -d "$stage" || { echo "Error: could not unpack $f." >&2; rm -rf "$tmp" "$stage"; return 1; }
      elif tar -tf "$tmp/$f" >/dev/null 2>&1; then
        tar -xf "$tmp/$f" -C "$stage" || { echo "Error: could not unpack $f." >&2; rm -rf "$tmp" "$stage"; return 1; }
      else
        echo "Error: neither unzip nor tar can unpack $f." >&2
        rm -rf "$tmp" "$stage"
        return 1
      fi
    done <<< "$files"
    rm -rf "$tmp"
    if [[ ! -x "$stage/bin/limactl.exe" ]]; then
      echo "Error: the download unpacked without bin/limactl.exe; nothing was installed." >&2
      rm -rf "$stage"
      return 1
    fi
    printf '%s\n' "$AGENT_VM_LIMA_FORK_TAG" > "$stage/.agent-vm-lima-tag"
    if [[ -e "$dir" ]]; then
      old="$dir.old.$$"
      if ! mv "$dir" "$old" 2>/dev/null; then
        echo "Error: could not replace the Lima install in $dir: stop the running VMs ('agent-vm list'), then retry." >&2
        rm -rf "$stage"
        return 1
      fi
    fi
    if ! mv "$stage" "$dir"; then
      [[ -n "$old" ]] && mv "$old" "$dir"
      rm -rf "$stage"
      return 1
    fi
    [[ -n "$old" ]] && rm -rf "$old"
    bin="$dir/bin"
    echo "Lima $AGENT_VM_LIMA_FORK_TAG is installed at $bin."
  fi
  case ":$PATH:" in
    *":$bin:"*) ;;
    *)
      export PATH="$bin:$PATH"
      echo "Added $bin to PATH for this shell. To keep it, add this line to ~/.bash_profile:"
      printf '  export PATH="%s:$PATH"\n' "$bin" ;;
  esac
}

# On Windows, when the Lima that _agent_vm_install_fork_windows put in place
# is of another tag than AGENT_VM_LIMA_FORK_TAG, offer to replace it. Never
# fails setup: the installed one keeps working.
_agent_vm_offer_fork_windows_update() {
  _agent_vm_on_windows || return 0
  local dir="${AGENT_VM_LIMA_DIR:-$HOME/.local/share/lima-sylvinus}" have
  [[ -x "$dir/bin/limactl.exe" ]] || return 0
  have="$(cat "$dir/.agent-vm-lima-tag" 2>/dev/null)"
  [[ "$have" != "$AGENT_VM_LIMA_FORK_TAG" ]] || return 0
  _agent_vm_have_tty || { echo "Note: Lima ${have:-(unknown version)} in $dir; 'agent-vm setup' in a terminal offers $AGENT_VM_LIMA_FORK_TAG." >&2; return 0; }
  [[ "$(_agent_vm_ask_yn "Update the Lima in $dir from ${have:-an unknown version} to $AGENT_VM_LIMA_FORK_TAG?" Y)" == "1" ]] || return 0
  _agent_vm_install_fork_windows || echo "Warning: the update failed; the installed Lima stays." >&2
  hash -r 2>/dev/null
  return 0
}

# AGENT_VM_UNSAFE_WRITABLE_GIT=1, or --unsafe-writable-git for one command,
# turns the protection off, for those who let the agent commit in the shared
# project. Only the host can ask for it: a setting in a file of the project
# would be one the VM can write. _agent_vm_ensure_running sets
# _agent_vm_unsafe_git_flag, as a local, for the flag.
_agent_vm_writable_git_optout() {
  [[ "${AGENT_VM_UNSAFE_WRITABLE_GIT:-}" == 1 || -n "${_agent_vm_unsafe_git_flag:-}" ]]
}

# What turned it off, to name it back to the user.
_agent_vm_writable_git_why() {
  if [[ -n "${_agent_vm_unsafe_git_flag:-}" ]]; then
    printf '%s\n' "--unsafe-writable-git"
  else
    printf '%s\n' "AGENT_VM_UNSAFE_WRITABLE_GIT=1"
  fi
}

_agent_vm_writable_git_warning() {
  cat <<EOF
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! WARNING: $(_agent_vm_writable_git_why). The VM can write every .git.
!!
!! The agent can change .git/config and .git/hooks in the shared folders, and
!! git on this machine runs what they name: on your next commit, and whenever
!! your editor or shell prompt calls git. That is running commands on your
!! host, outside the VM. Without it, .git stays read-only.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
}

# --- setup: a Lima that keeps .git read-only ------------------------------------
# Run by `setup` once Lima is there, and by nothing else: nothing to do when it
# already protects .git. Otherwise it says why that matters and, with a
# terminal to ask on, offers to install the build that has it: the formula
# with Homebrew, the release zips on Windows.
#
# brew refuses the formula next to its own lima (both install limactl) and asks
# for that one to be unlinked. Unlinking keeps it installed, so
# `brew uninstall lima-sylvinus && brew link lima` goes back. VMs are not
# touched either way. This never fails setup: the VMs work without it.
_agent_vm_offer_git_protection() {
  _agent_vm_offer_fork_windows_update
  local st=0
  _agent_vm_lima_protects_git || st=$?
  [[ "$st" == 0 ]] && return 0
  if [[ "$st" == 2 ]]; then
    echo "Warning: cannot tell whether this Lima keeps .git read-only: 'limactl validate' gave no answer agent-vm knows. A start with writable shares stops until it can tell ('agent-vm doctor')." >&2
    return 0
  fi
  _agent_vm_git_protection_hint | _agent_vm_box "Lima cannot keep .git read-only"
  local without="Continuing without .git protection: every start with writable shares will ask first." unlinked=""
  if _agent_vm_on_windows; then
    if ! _agent_vm_have_tty \
       || [[ "$(_agent_vm_ask_yn "Download the Lima build that has it now (both Windows zips, about 60 MB)?" Y)" != "1" ]]; then
      echo "$without" >&2
      return 0
    fi
    if ! _agent_vm_install_fork_windows; then
      echo "Warning: the download failed. $without" >&2
      return 0
    fi
  else
    if ! command -v brew >/dev/null 2>&1 || ! _agent_vm_have_tty \
       || [[ "$(_agent_vm_ask_yn "Install $AGENT_VM_LIMA_FORMULA now (built from source, takes a few minutes)?" Y)" != "1" ]]; then
      echo "$without" >&2
      return 0
    fi
    if brew list --formula lima >/dev/null 2>&1; then
      brew unlink lima && unlinked=1
    fi
    if ! brew install "$AGENT_VM_LIMA_FORMULA"; then
      # Unlinked and nothing in its place would leave no limactl at all.
      [[ -n "$unlinked" ]] && brew link lima
      echo "Warning: the install failed. $without" >&2
      return 0
    fi
  fi
  hash -r 2>/dev/null
  if _agent_vm_lima_protects_git; then
    echo "Lima now keeps every .git read-only for the VMs."
  else
    echo "Warning: the limactl on PATH ($(_agent_vm_limactl_path)) still cannot keep .git read-only." >&2
    echo "  Another Lima install comes first on PATH. $without" >&2
  fi
  return 0
}

# --- git on this machine: repositories not named .git ---------------------------
# readonlyNames protects a name, and a bare repository has none: a folder with
# HEAD, objects/ and refs/ is a repository to git, found by the same upward
# search from the current directory as a .git. Its config then applies, and
# some of it names commands git runs: core.pager on `git log`, for one. The VM
# can create such a folder anywhere in a share. safe.bareRepository=explicit (git 2.38+)
# makes git use a bare repository only when --git-dir or GIT_DIR names it.

# git, for agent-vm's own calls in a directory the VM can write. The VM may have
# planted a repository there: a bare one, whatever the user's
# safe.bareRepository, or a .git where Lima cannot protect it. -c is honoured
# for safe.bareRepository (command-line config is trusted, a repository's own
# is not), which refuses the bare one. core.fsmonitor=false stops the command
# a repository's config names from running on commands that read the index,
# and --no-pager the one pager.<cmd> and core.pager would start on a terminal.
_agent_vm_git_untrusted() {
  git --no-pager -c safe.bareRepository=explicit -c core.fsmonitor=false "$@"
}

# ok, unset, old (git before 2.38, which ignores the setting) or nogit. Read
# from /, outside any repository: git only honours the setting from the system
# and global config, so a repository's own config must not answer.
_agent_vm_bare_repo_state() {
  command -v git >/dev/null 2>&1 || { echo nogit; return 0; }
  local v
  v="$(git --version 2>/dev/null)"
  v="${v#git version }"
  v="${v%% *}"
  if ! _agent_vm_ver_ge "$v" 2.38.0; then
    echo old
  elif [[ "$(cd / && git config --get safe.bareRepository 2>/dev/null)" == "explicit" ]]; then
    echo ok
  else
    echo unset
  fi
}

# One paragraph per line, as for _agent_vm_git_protection_hint.
_agent_vm_bare_repo_hint() {
  cat <<'EOF'
Git treats any folder with HEAD, objects/ and refs/ as a repository, even without .git, and runs commands its config names (on `git log`, for one). A VM could create one in your projects, and the .git protection does not cover it.

This makes git ignore such folders unless named with --git-dir:
  git config --global safe.bareRepository explicit
EOF
}

# Run when a VM starts with writable shares. Offers to run the command above,
# when it can ask. Not set (no answer, a no, a git that ignores it): the
# security question of _agent_vm_confirm_unsafe, whose default stops the
# start. Fails when the start must stop. With the questions disabled, nothing
# is offered either: the global git config is not changed unasked. With $1
# set, the VM already runs, so a question would protect nothing: a warning
# only.
_agent_vm_check_bare_repo_setting() {
  local state
  state="$(_agent_vm_bare_repo_state)"
  case "$state" in
    ok|nogit) return 0 ;;
  esac
  if [[ -n "${1:-}" ]]; then
    echo "Warning: git on this machine uses repositories a VM creates under another name than .git ('agent-vm doctor' says more)." >&2
    return 0
  fi
  _agent_vm_bare_repo_hint | _agent_vm_box "Git: repositories not named .git"
  if [[ "$state" == old ]]; then
    echo "Warning: $(git --version) is older than 2.38 and ignores that setting." >&2
    _agent_vm_confirm_unsafe && return 0
    echo "Aborted. Upgrade git, then run the command above." >&2
    return 1
  fi
  if ! _agent_vm_prompts_disabled_by >/dev/null && _agent_vm_can_ask \
     && [[ "$(_agent_vm_ask_yn "Run it now? It changes your global git config." Y)" == "1" ]]; then
    if git config --global safe.bareRepository explicit && [[ "$(_agent_vm_bare_repo_state)" == "ok" ]]; then
      echo "Git on this machine now ignores repositories not named .git unless you name them."
      return 0
    fi
    echo "Warning: the setting did not take." >&2
  fi
  echo "Warning: not set. Until it is, git on this machine can run what a VM writes." >&2
  _agent_vm_confirm_unsafe && return 0
  echo "Aborted. Run the command above, then run agent-vm again." >&2
  return 1
}
