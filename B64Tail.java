import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Harmless self-test for CVE-2026-114938 ("Java4Shell"): drives the x86-64 AVX-512 VBMI Base64
 * intrinsic into its faulty padded-tail path and reports whether bytes past the decoded output
 * were overwritten. Every write stays inside an array allocated by this program.
 *
 * Build: javac --release 8 B64Tail.java   (runs on Java 8+)
 * Output: "VULNERABLE <changed> <java.version> <java.vendor> <trigger>"
 *      or "OK 0 <java.version> <java.vendor> -"
 */
public class B64Tail {
    // Current builds reach the faulty tail after 64 chars, older Java 17 builds only after 128
    // (higher length threshold); 256 also goes through the 256-char block loop first.
    private static final int[] LENGTHS = {64, 128, 256};
    // Padded leftovers of 1-3 chars make the stub's output length negative.
    private static final String[] TAILS = {"=", "==", "A=", "AA="};
    private static final int WARMUP = 200000;
    private static final byte CANARY = 0x55;
    private static volatile int sink;

    public static void main(String[] args) {
        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = Base64.getEncoder().encode(new byte[384]);   // 512 chars, no padding
        byte[] out = new byte[384];
        int changed = 0;
        String trigger = "-";
        search:
        for (int len : LENGTHS) {
            for (String tail : TAILS) {
                // (Re)warm before every attempt: a rejected input can deoptimize decode0.
                for (int i = 0; i < WARMUP; i++) sink += d.decode(valid, out);
                byte[] src = (repeat('A', len) + tail).getBytes(StandardCharsets.US_ASCII);
                int logical = len / 4 * 3;               // all Java may write before rejecting the tail
                byte[] dst = new byte[logical + 256];    // room for the 64-byte overrun
                Arrays.fill(dst, CANARY);
                try {
                    d.decode(src, dst);
                } catch (IllegalArgumentException expected) {
                }
                for (int i = logical; i < dst.length; i++) {
                    if (dst[i] != CANARY) changed++;
                }
                if (changed > 0) {
                    trigger = len + "xA" + tail;
                    break search;
                }
            }
        }
        System.out.println((changed > 0 ? "VULNERABLE " : "OK ") + changed + " "
                + System.getProperty("java.version") + " "
                + System.getProperty("java.vendor").replace(' ', '_') + " " + trigger);
    }

    private static String repeat(char c, int n) {
        char[] a = new char[n];
        Arrays.fill(a, c);
        return new String(a);
    }
}
