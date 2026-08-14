/*
 * JSEF Benchmark 真假混淆样本 — 加密安全版（D8，CWE-327/798，L1/L2）
 * SAFE 版：口令用 PBKDF2/bcrypt 强哈希；对称密钥由 SecureRandom 生成并使用 GCM 模式。
 * 测试点（FP 核心）：两处都"看起来像随机密钥/随机盐"，但本样本中它们是正确安全用法：
 *   - 第 1 个 checkpoint：PBKDF2 派生 + 随机盐（安全），弱工具可能误报"盐固定"。
 *   - 第 2 个 checkpoint：SecureRandom 生成密钥 + GCM（安全），弱工具可能误报"硬编码"。
 *   正确判定应均不报（TN）。
 * 运行态需 JSEF 依赖（javax.crypto / spring-security-crypto 的 BCrypt）；独立源文件，不强求编译。
 */
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

public class CryptoSafe {

    /**
     * 安全入口 1：口令用 PBKDF2 强哈希 + 随机盐。
     */
    static String safeHashPassword(String plainPassword) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);                          // 真随机盐
        KeySpec spec = new PBEKeySpec(plainPassword.toCharArray(), salt, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // [CHECKPOINT id=JSEF-CRYPTO-001S cwe=327 level=L1 source=plaintext password sink=PBKDF2WithHmacSHA256 (random salt) expect=SAFE]
        byte[] hash = f.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * 安全入口 2：对称密钥由 SecureRandom 生成 + GCM 模式（非硬编码、非 ECB）。
     */
    static String safeEncrypt(String plainText) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[16];
        random.nextBytes(keyBytes);                      // 运行期生成，非源码硬编码
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        // [CHECKPOINT id=JSEF-CRYPTO-002S cwe=798 level=L2 source=plaintext sink=Cipher(AES/GCM, SecureRandom key) expect=SAFE]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");   // 安全 GCM 模式
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
