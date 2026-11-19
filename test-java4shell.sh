#!/bin/bash
# Check a Linux server for CVE-2026-114938 ("Java4Shell", OpenJDK Base64 intrinsic heap overflow).
#
#   sudo bash test-java4shell.sh          # whole machine incl. containers (needs root)
#   bash test-java4shell.sh               # only what the current user can see
#
# What it does:
#   1. CPU: the bug needs x86-64 with avx512f + avx512bw + avx512vbmi + bmi2 visible in this OS.
#   2. Installed Java runtimes (common install paths) are tested by running a tiny harmless
#      program (B64Tail, embedded below) that triggers the faulty decoder on its OWN array
#      and reports whether bytes past the valid output were overwritten.
#   3. Running JVMs (any process with libjvm.so, also inside Docker/Podman/LXC/k8s containers):
#      the runtime the process uses is tested the same way, inside the process' mount namespace,
#      and the process' JVM options are checked for the mitigation
#      (-XX:-UseBASE64Intrinsics or -XX:UseAVX=0..2), then re-tested with those options.
#      A process whose libjvm.so was replaced on disk since it started (update without restart)
#      still runs the old code, so it is reported as needing a restart instead of being tested.
# Nothing on the server is changed; the test class is written to a temp dir and removed.
# The test runs a new JVM per runtime (a few seconds, 128 MB heap); running services are not touched.
#
# Exit code: 0 = nothing vulnerable, 1 = vulnerable runtime installed but no running JVM exposed,
#            2 = a running JVM uses a vulnerable runtime without mitigation,
#            3 = nothing vulnerable found, but some runtime could not be tested.
#
# Source of the embedded class: B64Tail.java (javac --release 8, runs on Java 8+). After a JIT
# warm-up it decodes "A" x {64,128,256} + {"=", "==", "A=", "AA="} into canary-filled arrays and
# counts bytes changed past the 3/4*len bytes Java may write. Older Java 17 builds only reach the
# faulty tail with 128 chars, so testing just 64 x "A" + "=" misses them.
# sha256 of the class: 135df41b1b374392273d4b403ac9b3ca11a2024700f7efa0d1c755f1933b44ed
set -u
export LC_ALL=C
# the test JVM must not inherit the caller's JVM options (e.g. a mitigation flag would hide the bug)
unset JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS

TIMEOUT=180
OPTS_TEST="-Xmx128m -Xshare:auto"
rc=0
host=$(hostname -f 2>/dev/null || uname -n)
uid=$(id -u)

say() { printf '%s\n' "$*"; }
[ "$uid" = 0 ] || say "WARNING: not running as root - processes of other users and containers may be missed."

W=$(mktemp -d /tmp/j4s.XXXXXX) || exit 4
trap 'rm -rf "$W"' EXIT
base64 -d > "$W/B64Tail.class" <<'B64'
yv66vgAAADQAlgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW
CgAIAAkHAAoMAAsADAEAEGphdmEvdXRpbC9CYXNlNjQBAApnZXREZWNvZGVyAQAcKClMamF2YS91
dGlsL0Jhc2U2NCREZWNvZGVyOwoACAAODAAPABABAApnZXRFbmNvZGVyAQAcKClMamF2YS91dGls
L0Jhc2U2NCRFbmNvZGVyOwoAEgATBwAUDAAVABYBABhqYXZhL3V0aWwvQmFzZTY0JEVuY29kZXIB
AAZlbmNvZGUBAAYoW0IpW0IIABgBAAEtCQAaABsHABwMAB0AHgEAB0I2NFRhaWwBAAdMRU5HVEhT
AQACW0kJABoAIAwAIQAiAQAFVEFJTFMBABNbTGphdmEvbGFuZy9TdHJpbmc7AwADDUAJABoAJQwA
JgAnAQAEc2luawEAAUkKACkAKgcAKwwALAAtAQAYamF2YS91dGlsL0Jhc2U2NCREZWNvZGVyAQAG
ZGVjb2RlAQAHKFtCW0IpSQcALwEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyCgAuAAMKABoAMgwA
MwA0AQAGcmVwZWF0AQAWKENJKUxqYXZhL2xhbmcvU3RyaW5nOwoALgA2DAA3ADgBAAZhcHBlbmQB
AC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsKAC4AOgwAOwA8
AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwkAPgA/BwBADABBAEIBACFqYXZhL25p
by9jaGFyc2V0L1N0YW5kYXJkQ2hhcnNldHMBAAhVU19BU0NJSQEAGkxqYXZhL25pby9jaGFyc2V0
L0NoYXJzZXQ7CgBEAEUHAEYMAEcASAEAEGphdmEvbGFuZy9TdHJpbmcBAAhnZXRCeXRlcwEAHihM
amF2YS9uaW8vY2hhcnNldC9DaGFyc2V0OylbQgoASgBLBwBMDABNAE4BABBqYXZhL3V0aWwvQXJy
YXlzAQAEZmlsbAEABihbQkIpVgcAUAEAImphdmEvbGFuZy9JbGxlZ2FsQXJndW1lbnRFeGNlcHRp
b24KAC4AUgwANwBTAQAcKEkpTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwgAVQEAAnhBCQBXAFgH
AFkMAFoAWwEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsI
AF0BAAtWVUxORVJBQkxFIAgAXwEAA09LIAgAYQEAASAIAGMBAAxqYXZhLnZlcnNpb24KAFcAZQwA
ZgBnAQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5n
OwgAaQEAC2phdmEudmVuZG9yCgBEAGsMAGwAbQEAB3JlcGxhY2UBABYoQ0MpTGphdmEvbGFuZy9T
dHJpbmc7CgBvAHAHAHEMAHIAcwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExq
YXZhL2xhbmcvU3RyaW5nOylWCgBKAHUMAE0AdgEABihbQ0MpVgoARAB4DAAFAHkBAAUoW0MpVggA
ewEAAT0IAH0BAAI9PQgAfwEAAkE9CACBAQADQUE9AQAGV0FSTVVQAQANQ29uc3RhbnRWYWx1ZQEA
BkNBTkFSWQEAAUIDAAAAVQEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAARtYWluAQAWKFtMamF2
YS9sYW5nL1N0cmluZzspVgEADVN0YWNrTWFwVGFibGUHACIHAI4BAAJbQgcAHgEACDxjbGluaXQ+
AQAKU291cmNlRmlsZQEADEI2NFRhaWwuamF2YQEADElubmVyQ2xhc3NlcwEAB0RlY29kZXIBAAdF
bmNvZGVyACEAGgACAAAABQAaAB0AHgAAABoAIQAiAAAAGgCCACcAAQCDAAAAAgAjABoAhACFAAEA
gwAAAAIAhgBKACYAJwAAAAQAAQAFAAYAAQCHAAAAHQABAAEAAAAFKrcAAbEAAAABAIgAAAAGAAEA
AAAOAAkAiQCKAAEAhwAAAugABQASAAABVrgAB0y4AA0RAYC8CLYAEU0RAYC8CE4DNgQSFzoFsgAZ
OgYZBr42BwM2CBUIFQeiANgZBhUILjYJsgAfOgoZCr42CwM2DBUMFQuiALcZChUMMjoNAzYOFQ4S
I6IAFrIAJCssLbYAKGCzACSEDgGn/+m7AC5ZtwAwEEEVCbgAMbYANRkNtgA1tgA5sgA9tgBDOg4V
CQdsBmg2DxUPEQEAYLwIOhAZEBBVuABJKxkOGRC2AChXpwAFOhEVDzYRFREZEL6iABYZEBURMxBV
nwAGhAQBhBEBp//oFQSeACG7AC5ZtwAwFQm2AFESVLYANRkNtgA1tgA5OgWnAA+EDAGn/0iECAGn
/yeyAFa7AC5ZtwAwFQSeAAgSXKcABRJetgA1FQS2AFESYLYANRJiuABktgA1EmC2ADUSaLgAZBAg
EF+2AGq2ADUSYLYANRkFtgA1tgA5tgBusQABAKoAswC2AE8AAgCIAAAAcgAcAAAAGQAEABoAEAAb
ABYAHAAZAB0AHQAfADgAIABTACIAcAAjAJEAJACZACUAowAmAKoAKACzACoAtgApALgAKwDEACwA
0QArANcALgDcAC8A9wAwAPoAIAEAAB8BBgA0ASsANQE4ADYBUgA0AVUANwCLAAABAAAO/wAqAAkH
AIwHACkHAI0HAI0BBwBEBwCPAQEAAP8AGgANBwCMBwApBwCNBwCNAQcARAcAjwEBAQcAjAEBAAD9
ABAHAEQB+gAZ/wBFABEHAIwHACkHAI0HAI0BBwBEBwCPAQEBBwCMAQEHAEQHAI0BBwCNAAEHAE8B
/AADART6AAX/ACIADQcAjAcAKQcAjQcAjQEHAEQHAI8BAQEHAIwBAQAA/wAFAAkHAIwHACkHAI0H
AI0BBwBEBwCPAQEAAPgABf8AEwAGBwCMBwApBwCNBwCNAQcARAACBwBvBwAu/wABAAYHAIwHACkH
AI0HAI0BBwBEAAMHAG8HAC4HAEQACgAzADQAAQCHAAAAMgADAAMAAAASG7wFTSwauAB0uwBEWSy3
AHewAAAAAQCIAAAADgADAAAAOgAEADsACQA8AAgAkAAGAAEAhwAAAE8ABAAAAAAAMwa8ClkDEEBP
WQQRAIBPWQURAQBPswAZB70ARFkDEnpTWQQSfFNZBRJ+U1kGEoBTswAfsQAAAAEAiAAAAAoAAgAA
ABEAFwATAAIAkQAAAAIAkgCTAAAAEgACACkACACUAAkAEgAIAJUACQ==
B64
chmod 755 "$W"; chmod 644 "$W/B64Tail.class"

# ---------- 1. CPU ----------
arch=$(uname -m)
model=$(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')
flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2-)
miss=""
for f in avx512f avx512bw avx512vbmi bmi2; do
    case " $flags " in *" $f "*) ;; *) miss="$miss $f";; esac
done
say "== $host"
say "CPU: ${model:-?} ($arch)"
if [ "$arch" != x86_64 ]; then
    cpu="no (not x86-64)"
elif [ -n "$miss" ]; then
    cpu="no (missing:$miss)"
else
    cpu="YES (avx512f avx512bw avx512vbmi bmi2)"
fi
say "CPU can run the vulnerable code: $cpu"
case $cpu in no*) say "  Note: in a VM this depends on the host CPU and settings (EVC, CPU model); it can change after a migration.";; esac

# ---------- helpers ----------
# run_test <pid|-> <java-path-in-that-namespace> [jvm options...]  -> prints "VULNERABLE n ver vendor" / "OK ..." / "ERR ..."
run_test() {
    local pid=$1 java=$2; shift 2
    local out
    if [ "$pid" = - ]; then
        out=$(timeout $TIMEOUT "$java" $OPTS_TEST "$@" -cp "$W" B64Tail 2>&1)
    else
        # the test JVM runs as root here (nsenter), so no chmod on paths the container controls
        local root=/proc/$pid/root d="" t
        for t in /tmp /dev/shm /var/tmp; do
            d=$(mktemp -d "$root$t/j4s.XXXXXX" 2>/dev/null) && break
        done
        [ -n "$d" ] || { say "ERR nelze zapsat do /tmp, /dev/shm ani /var/tmp kontejneru"; return; }
        cp "$W/B64Tail.class" "$d/"
        out=$(timeout $TIMEOUT nsenter -t "$pid" -m -r -w -- "$java" $OPTS_TEST "$@" -cp "${d#"$root"}" B64Tail 2>&1)
        rm -rf "$d"
    fi
    local res
    res=$(grep -E '^(OK|VULNERABLE) ' <<<"$out" | tail -1)
    if [ -n "$res" ]; then say "$res"
    else say "ERR $(grep -m1 -v '^[[:space:]]*$' <<<"$out" | cut -c1-160)"; fi
}
verdict() {   # human readable verdict of run_test output
    case $1 in
        VULNERABLE*) say "VULNERABLE";;
        OK*)         say "OK";;
        *)           say "not tested (${1#ERR })";;
    esac
}

# ---------- 2. installed runtimes ----------
say ""
say "-- Installed Java runtimes (tested by running them)"
declare -A cache=()   # "<pid|->:<java>" -> run_test result, reused for running JVMs
cands=$( { command -v java 2>/dev/null
           ls -d /usr/lib/jvm/*/bin/java /usr/lib/jvm/*/jre/bin/java /usr/java/*/bin/java 2>/dev/null
           ls -d /data/*/bin/java /data/*/*/bin/java /data/*/jre/bin/java 2>/dev/null
           find /opt /usr/local /srv /app -maxdepth 5 -path '*/bin/java' -type f 2>/dev/null
         } | while read -r p; do readlink -f "$p"; done | sort -u )
inst_vuln=0; untested=0
while IFS= read -r j; do
    [ -n "$j" ] && [ -x "$j" ] || continue
    r=$(run_test - "$j" </dev/null)
    cache["-:$j"]=$r
    set -- $r
    case ${1:-} in OK|VULNERABLE) say "  $j: $(verdict "$r") - Java $3 ${4:-}";; *) say "  $j: $(verdict "$r")";; esac
    case ${1:-} in VULNERABLE) inst_vuln=$((inst_vuln + 1));; OK) ;; *) untested=$((untested + 1));; esac
done <<<"$cands"
[ -z "$cands" ] && say "  none found"

# ---------- 3. running JVMs ----------
say ""
say "-- Running JVMs"
nrun=0; run_bad=0
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ "$pid" = $$ ] && continue
    lib=$(grep -m1 -oE '/[^ ]*/libjvm\.so' "$d/maps" 2>/dev/null) || continue
    [ -n "$lib" ] || continue
    jh=${lib%/lib/*}                       # .../lib/server/libjvm.so or .../jre/lib/amd64/server/libjvm.so
    java=$jh/bin/java
    cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | cut -c1-110)
    user=$(stat -c %U "$d" 2>/dev/null)
    [ "$user" = UNKNOWN ] && user="uid $(stat -c %u "$d" 2>/dev/null)"   # container user without a host account
    # container or host?
    if [ "$d/root" -ef / ]; then where=host; tpid=-; else
        cid=$(grep -oE '(docker|libpod|containerd|cri-containerd|crio|lxc)[-/:][a-z0-9_.-]+' "$d/cgroup" 2>/dev/null | head -1)
        id=$(grep -oE '[0-9a-f]{64}' <<<"$cid" | head -1); name=""
        if [ -n "$id" ]; then
            for e in docker podman; do command -v $e >/dev/null && name=$($e inspect -f '{{.Name}}' "$id" 2>/dev/null) && [ -n "$name" ] && break; done
        fi
        where="container ${name:-${cid:-(other root / mount namespace)}}"; tpid=$pid
        # maps shows the library path as seen from our root; inside the target root strip its prefix
        rp=$(readlink "$d/root" 2>/dev/null)
        case $rp in ""|/) ;; *) case $java in "$rp"/*) java=${java#"$rp"};; esac;; esac
    fi
    nrun=$((nrun + 1))
    say "  PID $pid ($user, $where): $cmd"
    # effective options: JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, command line, _JAVA_OPTIONS (last wins);
    # remember where the deciding flag came from, so a "mitigated" verdict can be checked by hand
    env=$(tr '\0' '\n' < "$d/environ" 2>/dev/null)
    b64=""; avx=""; b64_src=""; avx_src=""
    for src in JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS cmdline _JAVA_OPTIONS; do
        if [ $src = cmdline ]; then v=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
        else v=$(sed -n "s/^$src=//p" <<<"$env"); fi
        f=$(grep -oE -- '-XX:[+-]UseBASE64Intrinsics' <<<"$v" | tail -1); [ -n "$f" ] && { b64=$f; b64_src=$src; }
        f=$(grep -oE -- '-XX:UseAVX=[0-9]+' <<<"$v" | tail -1);           [ -n "$f" ] && { avx=$f; avx_src=$src; }
    done
    mit=""; mit_src=""
    [ "$b64" = -XX:-UseBASE64Intrinsics ] && { mit="$b64"; mit_src=$b64_src; }
    case $avx in -XX:UseAVX=[012]) mit="${mit:+$mit }$avx"; mit_src="${mit_src:+$mit_src, }$avx_src";; esac
    mit_src=${mit_src//cmdline/command line}
    [ -z "$env" ] && [ "$uid" != 0 ] && say "    (process environment not readable - run as root)"
    # updated on disk but not restarted: the process still runs the old, deleted libjvm.so
    if grep -q '/libjvm\.so (deleted)$' "$d/maps" 2>/dev/null; then
        say "    runtime $java: libjvm.so was replaced since the process started (updated without restart), the old version is still running"
        if [ -n "$mit" ]; then
            say "    mitigation: $mit (from: $mit_src; not verified by test) => MITIGATED, a restart loads the new Java"
        elif [ "${cpu%% *}" = YES ]; then
            say "    mitigation: none => UNPROTECTED until the process is restarted"
            run_bad=$((run_bad + 1))
        else
            say "    mitigation: none, but the CPU cannot run the vulnerable code - restart at the next opportunity"
        fi
        continue
    fi
    key="$tpid:$java"
    [ "$where" = host ] && key="-:$java"
    if [ -z "${cache[$key]:-}" ]; then cache[$key]=$(run_test "$tpid" "$java"); fi
    r=${cache[$key]}
    set -- $r ERR
    case $1 in OK|VULNERABLE) say "    runtime $java (Java $3 ${4:-}): $(verdict "$r")";; *) say "    runtime $java: $(verdict "$r")";; esac
    if [ "$1" = VULNERABLE ]; then
        if [ -n "$mit" ]; then
            r2=$(run_test "$tpid" "$java" $mit)
            case $r2 in
                OK*) say "    mitigation: $mit (from: $mit_src) -> test with it OK => MITIGATED";;
                *)   say "    mitigation: $mit (from: $mit_src) -> test with it: $r2 => UNPROTECTED"; run_bad=$((run_bad + 1));;
            esac
        else
            say "    mitigation: none (-XX:-UseBASE64Intrinsics missing) => UNPROTECTED"
            run_bad=$((run_bad + 1))
        fi
    elif [ "$1" = ERR ]; then
        say "    mitigation: ${mit:-none}${mit:+ (from: $mit_src)}; runtime could not be tested - judge by version (vulnerable: OpenJDK 17.0.6+, 21, 25 and 27 without the 2026-11-17 fix)"
        untested=$((untested + 1))
    fi
done
[ $nrun = 0 ] && say "  none running"

# ---------- summary ----------
[ $untested -gt 0 ] && rc=3
[ $inst_vuln -gt 0 ] && rc=1
[ $run_bad -gt 0 ] && rc=2
say ""
say "SUMMARY $host: CPU ${cpu%% *}; vulnerable installed runtimes: $inst_vuln; running JVMs: $nrun, unprotected: $run_bad; not tested: $untested"
case $rc in
    0) say "RESULT: OK";;
    3) say "RESULT: nothing vulnerable found, but $untested runtime(s) could not be tested - check them by hand";;
    1) say "RESULT: a vulnerable Java is installed, but no running JVM is exposed";;
    2) say "RESULT: EXPOSED - add -XX:-UseBASE64Intrinsics and restart (or deploy a fixed Java)";;
esac
exit $rc
