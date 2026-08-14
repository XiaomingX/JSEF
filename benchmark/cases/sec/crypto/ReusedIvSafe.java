/*
 * JSEF Benchmark 安全样本 — AES-GCM 重用 IV（A02，CWE-329，L3）
 * SAFE 版：每次加密使用 SecureRandom 生成唯一 IV。
 * 测试点：强 SAST/LLM 应识别 IV 每加密随机生成而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class ReusedIvSafe {

    private static final byte[] KEY = "mysecretkey1234".getBytes();

    /**
     * 安全入口：每加密随机生成 IV。
     */
    static String encrypt(String plainText) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[12];
        rnd.nextBytes(iv);   // 唯一 IV
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        // [CHECKPOINT id=JSEF-A02-002S cwe=329 level=L3 source=SecureRandom IV (unique per encrypt) sink=Cipher(AES/GCM, random IV) expect=SAFE]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
