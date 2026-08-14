/*
 * JSEF Benchmark 样本 — AES/ECB 模式（A02，CWE-327，L2）
 * 运行态需 JSEF 依赖（javax.crypto）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实模式推断利用。
 *
 * 知识点（A02 加密缺陷，CWE-327 危险加密模式）：
 *   ECB 模式相同明文块生成相同密文块，泄露明文结构，可模式推断。应使用 GCM/CTR 等。
 *   污点：明文 → Cipher.getInstance("AES/ECB") → doFinal。仿 CryptoHardcodedKey 风格。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EcbMode {

    private static final String KEY = "mysecretkey1234";

    /**
     * 危险入口：AES/ECB 模式加密。
     */
    static String encrypt(String plainText) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
        // [CHECKPOINT id=JSEF-A02-004 cwe=327 level=L2 source=plaintext sink=Cipher(AES/ECB) expect=VULN]
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");   // 危险 ECB 模式
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
