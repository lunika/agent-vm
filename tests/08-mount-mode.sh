# =============================================================================
section "project mount mode (--readonly is a host-side flag)"
# =============================================================================
# The read-only decision has to reach Lima's mount config, the only place the
# guest cannot undo it. Assert on the JSON handed to limactl, so a revert to a
# guest-side `mount -o remount,ro` fails here instead of passing quietly.
mounts_default="$(_agent_vm_build_mounts_json agent-vm-t "$PROJ")"
mounts_rw="$(_agent_vm_build_mounts_json agent-vm-t "$PROJ" true)"
mounts_ro="$(_agent_vm_build_mounts_json agent-vm-t "$PROJ" false)"

check "default is a writable project mount" \
  "$mounts_default" "[{$(mnt "$PROJ"), \"writable\": true}]"
check "an explicit true agrees with the default" "$mounts_rw" "$mounts_default"
check "false marks the project mount read-only" \
  "$mounts_ro" "[{$(mnt "$PROJ"), \"writable\": false}]"

# The mode must ride on the project entry, not on whatever happens to be first
# once ~/.agent-vm/volumes contributes extra mounts.
mkdir -p "$SB/extra-vol"
printf '%s:ro\n' "$SB/extra-vol" > "$HOME/.agent-vm/volumes"
mounts_ro_vols="$(_agent_vm_build_mounts_json agent-vm-t "$PROJ" false)"
rm -f "$HOME/.agent-vm/volumes"
case "$mounts_ro_vols" in
  "[{$(mnt "$PROJ"), \"writable\": false},"*"extra-vol"*)
    pass "read-only project mount keeps the ~/.agent-vm/volumes entries" ;;
  *) fail "volumes entries lost or reordered: $mounts_ro_vols" ;;
esac

# .git protection: Lima refuses readonlyNames unless EVERY mount uses the
# builtin driver, so the volumes entries need it as much as the project.
SSHFS_RO='"sshfs": {"sftpDriver": "builtin", "cache": false, "readonlyNames": [".git", ".hg"]}'
printf '%s:/mnt/v:rw\n' "$SB/extra-vol" > "$HOME/.agent-vm/volumes"
mounts_prot="$(_agent_vm_build_mounts_json agent-vm-t "$PROJ" true 1)"
rm -f "$HOME/.agent-vm/volumes"
case "$mounts_prot" in
  "[{$(mnt "$PROJ"), \"writable\": true, $SSHFS_RO}, "*) pass "protected: the project entry carries readonlyNames" ;;
  *) fail "protected project entry: $mounts_prot" ;;
esac
check "protected: every entry has the builtin driver" \
  "$(printf '%s' "$mounts_prot" | grep -o '"sftpDriver": "builtin"' | wc -l | tr -d ' ')" "2"
case "$(_agent_vm_mounts_expr '[]' 1)" in
  '.mountType = "reverse-sshfs" | .mounts = []') pass "protected: the mount type is reverse-sshfs" ;;
  *) fail "protected expression: $(_agent_vm_mounts_expr '[]' 1)" ;;
esac
# Without the protection, a reverse-sshfs left by a Lima that had it must go:
# without readonlyNames it is the weaker mount type.
case "$(_agent_vm_mounts_expr '[]' '')" in
  'del(.mountType) | .mounts = []') pass "unprotected: back to Lima's default mount type" ;;
  *) fail "unprotected expression: $(_agent_vm_mounts_expr '[]' '')" ;;
esac

# Read-only is only a real boundary for mount types the host enforces. Lima
# applies it inside the guest for reverse-sshfs and for virtiofs under QEMU,
# where root can remount it rw. Answered from what `limactl list` reports for
# the VM, "<VM type> <mount type>" ($1), never from the guest: this stub's
# guest claims 9p, which must not count.
mount_types() {
  cat > "$SB/bin/limactl" <<STUB
#!/usr/bin/env bash
[ "\$1" = shell ] && { echo 9p; exit 0; }
case "\$*" in *"json .Config.Mounts"*) printf '%s\n' "\${MT_LIVE:-$1 null}"; exit 0 ;; esac
[ "\$1" = list ] && { printf '%s\n' "$1"; exit 0; }
if [ "\$1" = validate ]; then
  if [ -n "\${MT_PROTECTS:-}" ]; then
    echo 'level=fatal msg="failed to validate YAML file \`probe.yaml\`: field \`mounts[0].sshfs.readonlyNames\` must contain file names, got \`a/b\`"' >&2
    exit 1
  fi
  echo 'level=warning msg="Non-strict YAML detected; please check for typos" error="[3:158] unknown field \"readonlyNames\""' >&2
  exit 0
fi
exit 1
STUB
  chmod +x "$SB/bin/limactl"
  _agent_vm_mount_is_host_enforced agent-vm-t
  printf '%s' "$?"
}
check "virtiofs on vz is host-enforced"      "$(mount_types 'vz virtiofs')"   "0"
check "virtiofs under QEMU is not"          "$(mount_types 'qemu virtiofs')" "1"
check "virtiofs, VM type unknown: undecided" "$(mount_types ' virtiofs')"     "2"
check "9p on QEMU is host-enforced"         "$(mount_types 'qemu 9p')"       "0"
check "reverse-sshfs is not"                "$(mount_types 'vz reverse-sshfs')" "1"
check "an empty answer is undecided"        "$(mount_types '')"              "2"
check "an unknown VM type is undecided"     "$(mount_types 'wsl2 wsl2')"     "2"
# Left unset, Lima's driver picks it at start: virtiofs on vz, 9p on QEMU for
# a VM made by Lima 1.0 or later (its lima-version file), reverse-sshfs before.
check "unset on vz: virtiofs, enforced"     "$(mount_types 'vz <nil>')"      "0"
mkdir -p "$SB/lima-home/agent-vm-t"
echo 2.1.0 > "$SB/lima-home/agent-vm-t/lima-version"
# Not on a Windows host, where QEMU has no 9p (tests/18-windows.sh).
if _agent_vm_on_windows; then
  printf '  skip unset on QEMU, Lima >= 1.0: 9p (a Windows host has no 9p)\n'
else
  check "unset on QEMU, Lima >= 1.0: 9p, enforced" "$(LIMA_HOME="$SB/lima-home" mount_types 'qemu <nil>')" "0"
fi
echo 0.23.2 > "$SB/lima-home/agent-vm-t/lima-version"
check "unset on QEMU, Lima < 1.0: reverse-sshfs, not" "$(LIMA_HOME="$SB/lima-home" mount_types 'qemu <nil>')" "1"
rm -f "$SB/lima-home/agent-vm-t/lima-version"
check "unset on QEMU, no lima-version: reverse-sshfs, not" "$(LIMA_HOME="$SB/lima-home" mount_types 'qemu')" "1"
# Served by the builtin server of a Lima with readonlyNames, it is. The guest
# cannot tell the servers apart: the record of the applied mounts does.
mkdir -p "$HOME/.agent-vm"
printf '[{"location": "%s", "writable": false, %s}]\n' "$PROJ" "$SSHFS_RO" > "$HOME/.agent-vm/.agent-vm-mounts-agent-vm-t"
LIVE_OK='qemu reverse-sshfs [{"location":"/p","writable":false,"sshfs":{"cache":false,"sftpDriver":"builtin","readonlyNames":[".git",".hg"]}}]'
check "reverse-sshfs with readonlyNames is" "$(MT_PROTECTS=1 MT_LIVE="$LIVE_OK" mount_types 'qemu reverse-sshfs')" "0"
# Recorded so, but Lima has a share without them, set outside agent-vm: not.
# Built apart: bash 3.2 brace-expands {...,...} in a quoted $( ).
live="${LIVE_OK%]},{\"location\":\"/elsewhere\",\"writable\":true}]"
check "recorded with readonlyNames, a share in Lima's config without them: not" \
  "$(MT_PROTECTS=1 MT_LIVE="$live" mount_types 'qemu reverse-sshfs')" "1"
# Recorded so, and so in Lima's config, but served by a Lima without them (a
# stock limactl installed since): not.
check "recorded with readonlyNames, a Lima without them: not" "$(MT_LIVE="$LIVE_OK" mount_types 'qemu reverse-sshfs')" "1"
rm -f "$HOME/.agent-vm/.agent-vm-mounts-agent-vm-t"

# Each part of Lima's config the protection needs (see
# _agent_vm_live_shares_why), and what is said when one is missing.
why() { _agent_vm_live_shares_why "$@" >/dev/null && echo ok || echo not; }
check "live: every share with the builtin server and the names" "$(why "$LIVE_OK")" "ok"
check "live: another mount type" "$(why "${LIVE_OK/reverse-sshfs/virtiofs}")" "not"
case "$(_agent_vm_live_shares_why "${LIVE_OK/reverse-sshfs/virtiofs}")" in
  *"mount type is virtiofs"*) pass "live: and says it is the mount type" ;;
  *) fail "live: mount type: $(_agent_vm_live_shares_why "${LIVE_OK/reverse-sshfs/virtiofs}")" ;;
esac
check "live: a share without the builtin server" "$(why "${LIVE_OK/\"sftpDriver\":\"builtin\",/}")" "not"
check "live: other names than those asked" "$(why "$LIVE_OK" '[".git", ".hg", "tools"]')" "not"
check "live: the names asked" "$(why "$LIVE_OK" '[".git", ".hg"]')" "ok"
live='qemu reverse-sshfs [{"location":"/p","sshfs":{"sftpDriver":"builtin","readonlyNames":[".git",".hg","location"]}},{"location":"/q","sshfs":{"sftpDriver":"builtin","readonlyNames":[".git",".hg","location"]}}]'
check "live: a name 'location' does not split a share" "$(why "$live" '[".git", ".hg", "location"]')" "ok"
check "live: no share at all" "$(why 'vz virtiofs null')" "ok"
fields() { local live_vmtype live_mtype live_json; _agent_vm_live_fields "$1" && echo "$live_vmtype|$live_mtype|$live_json" || echo none; }
check "live: the three fields" "$(fields 'vz reverse-sshfs [{"location":"/p"}]')" 'vz|reverse-sshfs|[{"location":"/p"}]'
check "live: no mount type" "$(fields 'qemu  null')|$(fields 'qemu null')" "qemu||null|qemu||null"
check "live: no JSON, no answer" "$(fields 'vz virtiofs')" "none"
check "live: Lima not answering" "$(why '')" "not"
# Restore the shared stub: mount_fstype replaced it with its own.
cat > "$SB/bin/limactl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$SB/bin/limactl"

# =============================================================================
section "unenforceable flags are gone, not just hidden"
# =============================================================================
# Both were removed for the same reason: they were applied inside the VM, where
# the agent has passwordless sudo and could undo them. --offline was iptables
# rules, --git-read-only a bind mount. Neither can come back without the
# enforcement moving to the host, so fail here if one reappears — including as
# a silently-ignored argument, which reads to a caller like it worked.
for flag in --offline --git-read-only --git-ro; do
  if grep -q -- "$flag" "$AGENT_VM_SH" "$SELF_DIR"/lib/*.sh; then
    fail "$flag still referenced in agent-vm.sh or lib/"
  else
    pass "no $flag left in agent-vm.sh or lib/"
  fi
  if agent-vm "$flag" shell >/dev/null 2>&1; then
    fail "$flag was silently accepted"
  else
    pass "$flag is rejected rather than ignored"
  fi
done
