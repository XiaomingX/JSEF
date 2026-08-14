/*
 * JSEF Benchmark 样本 — 硬编码密钥 + ECB 模式（D8，CWE-798/327，L2）
 * 运行态需 JSEF 依赖（javax.crypto）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实加密利用。
 *
 * 知识点（CAP-04，L2 多跳）：
 *   1) AES 密钥硬编码在源码常量中（CWE-798 硬编码凭证）；
 *   2) 使用 ECB 模式（CWE-327 危险加密模式，相同明文块得到相同密文块，可模式推断）。
 *   污点：明文 → Cipher.init(ENCRYPT_MODE, keySpec=硬编码, ECB) → doFinal。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class CryptoHardcodedKey {

    // 危险：硬编码密钥 + 固定 16 字节
    private static final String KEY = "mysecretkey1234";   // CWE-798

    /**
     * 危险入口：硬编码密钥 + ECB 模式加密。
     */
    static String encrypt(String plainText) throws Exception {
        // source：明文（不可信输入）
        byte[] keyBytes = KEY.getBytes();                 // 硬编码密钥
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        // [CHECKPOINT id=JSEF-CRYPTO-002 cwe=798 level=L2 source=plaintext sink=Cipher(AES/ECB, hardcoded key) expect=VULN]
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");   // 危险 ECB 模式
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
