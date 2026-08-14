/*
 * JSEF Benchmark 安全样本 — AES/ECB 模式（A02，CWE-327，L2）
 * SAFE 版：使用 AES/GCM 模式（带随机 IV）。
 * 测试点：强 SAST/LLM 应识别模式安全而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EcbModeSafe {

    private static final String KEY = "mysecretkey1234";

    /**
     * 安全入口：AES/GCM 模式。
     */
    static String encrypt(String plainText) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[12];
        rnd.nextBytes(iv);
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        // [CHECKPOINT id=JSEF-A02-004S cwe=327 level=L2 source=plaintext sink=Cipher(AES/GCM, random IV) expect=SAFE]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");   // 安全 GCM 模式
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
