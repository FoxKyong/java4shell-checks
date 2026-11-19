# Java4Shell exposure check (CVE-2026-114938)

On-box check for **Java4Shell**, a heap out-of-bounds write in the x86-64
AVX-512 VBMI Base64 decoder intrinsic of OpenJDK HotSpot, disclosed on
2026-11-17. A malformed Base64 string with a stray `=` makes the decoder write
62–63 bytes past its output array before Java rejects the input. Calif
demonstrated heap disclosure and pre-auth RCE in Keycloak, Jira, Confluence,
Artifactory, Jenkins and PingFederate in their default configurations.

A host is exposed only when **all** of these hold:

- an affected JVM: OpenJDK **17.0.6+**, **21**, **25**, **27** without the
  November 2026 fix (Oracle Java SE 8u511b33-perf and GraalVM too; standard
  Java 8 and Java 11 are not affected),
- an x86-64 CPU exposing `avx512f`, `avx512bw`, `avx512vbmi` and `bmi2`
  (Intel Xeon Ice Lake and newer, AMD Zen 4 and newer; ARM64 is not affected),
- attacker-controlled Base64 reaching `java.util.Base64` (Basic auth headers,
  tokens, uploads, …) in a JIT-compiled decoder.

Because the CPU decides, the same container image can be vulnerable on one
node and safe on another. Version lists alone are not enough, so the script
runs a harmless trigger on the real runtime and CPU.

## `test-java4shell.sh`

```
sudo bash test-java4shell.sh     # whole machine incl. containers
bash test-java4shell.sh          # only what the current user can see
```

1. **CPU**: are all four required features visible to this OS?
2. **Installed runtimes** (`PATH`, `/usr/lib/jvm`, `/usr/java`, `/opt`,
   `/usr/local`, `/srv`, `/app`, `/data`): each one is tested by running the
   embedded `B64Tail` class.
3. **Running JVMs**: every process that maps `libjvm.so`, also inside
   Docker / Podman / LXC / Kubernetes containers. The runtime the process uses
   is tested inside its mount namespace; then the process' effective options
   (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, command line, `_JAVA_OPTIONS`,
   last wins) are checked for a stopgap, and the runtime is re-tested with it.
   The output names where the flag came from, so a `MITIGATED` verdict can be
   checked by hand.

Verdicts: `VULNERABLE` / `OK` per runtime; for running JVMs on a vulnerable
runtime `MITIGATED` (stopgap active and confirmed by the re-test) or
`UNPROTECTED`. Example for one container:

```
  PID 12345 (root, container /keycloak): /opt/java/openjdk/bin/java -Dkc.config.built=true ...
    runtime /opt/java/openjdk/bin/java (Java 21.0.5 Eclipse_Adoptium): VULNERABLE
    mitigation: -XX:-UseBASE64Intrinsics (from: command line) -> test with it OK => MITIGATED
```

| Exit code | Meaning |
|---|---|
| 0 | nothing vulnerable |
| 1 | a vulnerable runtime is installed, but no running JVM is exposed |
| 2 | a running JVM uses a vulnerable runtime without a stopgap |
| 3 | nothing vulnerable found, but some runtime could not be tested |
| 4 | could not create a temp directory |

### What it does not touch

The script is read-only towards services: running JVMs are never attached to
or signalled. It starts a separate short-lived JVM per runtime (128 MB heap,
about a second each) and writes the test
class to a fresh temp directory (in a container: its `/tmp`, `/dev/shm` or
`/var/tmp`), which is removed afterwards. All overwritten bytes are inside an
array the test class allocated itself.

### Pitfalls it catches

- **Older Java 17 builds** reach the faulty code path only with 128 input
  characters, not 64. A probe that only tries `64 × "A" + "="` reports them
  as clean. The test tries 64, 128 and 256 characters with the tails `=`,
  `==`, `A=`, `AA=`.
- **Updated, not restarted**: a JVM whose `libjvm.so` was replaced on disk
  still runs the old code. Testing the new binary would say "OK", so such a
  process is reported as needing a restart instead.
- **Inherited options**: the test JVM does not inherit the caller's
  `JAVA_TOOL_OPTIONS` / `JDK_JAVA_OPTIONS` / `_JAVA_OPTIONS`, which could
  otherwise hide the bug.
- **Untested is not clean**: runtimes that could not be run are counted and
  turn exit code 0 into 3.

## Fix and stopgaps

Update to the fixed build of your vendor (Oracle `17.0.21.1`, `21.0.13.1`,
`25.0.5.1`, `27.0.1.1`; Temurin, Corretto, Zulu, Debian and others ship their
own), then **restart the JVMs and rebuild container images**. Products that
bundle a JRE need an update from their vendor.

Until then, start the JVM with one of:

- `-XX:-UseBASE64Intrinsics`: disables only the Base64 intrinsic, works on
  any architecture.
- `-XX:UseAVX=2`: disables AVX-512 entirely. **x86-64 only**; a JVM on ARM64
  does not recognise it and fails to start.

Do not use `-XX:DisableIntrinsic=_base64_decodeBlock` on its own; per Upwind
it stops the JVM from starting.

## Rebuilding the embedded class

`B64Tail.java` is the source of the base64 block in the script.

```
javac --release 8 B64Tail.java
sha256sum B64Tail.class          # put the hash in the script header
base64 -w76 B64Tail.class        # replace the block between <<'B64' and B64
```

The current class was built with the `javac` of Temurin 17.0.21.1. Other
compiler versions produce different bytes and a different hash.

## Verification status

- ✅ **Verified** on an AMD EPYC 9135 (Zen 5, AVX-512 VBMI) host running
  Docker: Temurin 17.0.11, 21.0.2, 21.0.5 and 21.0.10 in containers and a
  Debian 21.0.12.1 runtime on the host were reported vulnerable, and the
  re-test with `-XX:-UseBASE64Intrinsics` came out clean for all of them. The
  Java 17 runtime had been missed by a 64-character-only probe.
- ✅ **Verified** on a CPU without AVX-512 (AMD Zen 3) with Temurin 17.0.21.1:
  `OK`, detection of a replaced `libjvm.so` and ignoring of inherited JVM
  options.
- 📝 **Not yet verified**: a *fixed* build on an AVX-512 VBMI CPU reporting
  `OK`, a Java 8 runtime, the `-XX:UseAVX=2` path, Podman / LXC / Kubernetes
  containers.

## Responsible use

The script only runs a self-contained trigger on the local machine. It sends
nothing over the network and does not touch running services. Run it only on
systems you administer.

## References

- Calif: <https://calif.io/java4shell> (write-up and PoC)
- OpenJDK Vulnerability Advisory 2026-11-17:
  <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>
- Upwind lab notes:
  <https://www.upwind.io/blog/java4shell-what-we-know-now-and-what-comes-next>
- Blackpoint APG analysis:
  <https://blackpointcyber.com/blog/java4shell-cve-2026-114938-java-base64-decoder-flaw/>
- Earlier public fix proposal with the trigger: <https://github.com/openjdk/jdk/pull/32781>

## License

MIT, see [LICENSE](LICENSE).
