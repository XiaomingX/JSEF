/*
 * JSEF Benchmark 安全样本 — AES-GCM 重用 IV（A02，CWE-329，L3）
 * SAFE 版：每次加密使用 SecureRandom 生成唯一 IV，并通过外部配置传入密钥（消除硬编码）。
 *
 * 修复要点（对照 vuln）：
 *   ① IV 唯一性：每加密随机生成 12 字节 IV（GCM 推荐），杜绝重复 IV（key+nonce 对唯一）。
 *   ② 硬编码密钥消除：密钥从外部配置/环境变量加载，不内嵌源码（CWE-321 对照）。
 *      演示场景中提供 fallback 占位，真实部署须注入真实密钥。
 *
 * 测试点：强 SAST/LLM 应识别 IV 每加密随机生成、无硬编码密钥而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class ReusedIvSafe {

    // 演示：从环境变量加载密钥（真实部署须注入；源码中不内嵌密钥）
    private static final byte[] KEY = loadKeyFromConfig();

    private static byte[] loadKeyFromConfig() {
        String envKey = System.getenv("DEMO_AES_KEY");
        // 演示占位：真实部署必须提供 >= 16 字节的随机密钥（如 KMS/Vault 注入）
        return (envKey != null ? envKey : "demo-placeholder-key-32b!!!!!!")
                .getBytes();
    }

    /**
     * 安全入口：每加密随机生成 IV + 外部密钥。
     */
    static String encrypt(String plainText) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[12];
        rnd.nextBytes(iv); // 唯一 IV（GCM 推荐 96-bit）
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        // [CHECKPOINT id=JSEF-A02-002S cwe=329 level=L3 source=SecureRandom IV (unique per encrypt) sink=Cipher(AES/GCM, random IV, external key) expect=SAFE]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
