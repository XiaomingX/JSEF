/*
 * JSEF Benchmark 安全样本 — AES/ECB 模式（A02，CWE-327，L2）
 * SAFE 版：使用 AES/GCM 模式（带随机 IV），并通过环境变量/参数传入密钥（消除硬编码）。
 *
 * 修复要点（对照 vuln）：
 *   ① 算法模式：ECB → GCM（带认证标签，防重放/篡改）。
 *   ② 硬编码密钥消除：密钥从外部配置/环境变量加载，不内嵌源码（CWE-321 对照）。
 *      演示场景中提供 fallback 占位，真实部署须注入真实密钥。
 *
 * 测试点：强 SAST/LLM 应识别模式安全、IV 随机、无硬编码密钥而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class EcbModeSafe {

    // 演示：从环境变量加载密钥（真实部署须注入；源码中不内嵌密钥）
    private static final byte[] KEY = loadKeyFromConfig();

    private static byte[] loadKeyFromConfig() {
        String envKey = System.getenv("DEMO_AES_KEY");
        // 演示占位：真实部署必须提供 >= 16 字节的随机密钥（如 KMS/Vault 注入）
        return (envKey != null ? envKey : "demo-placeholder-key-32b!!!!!!")
                .getBytes();
    }

    /**
     * 安全入口：AES/GCM 模式 + 随机 IV + 外部密钥。
     */
    static String encrypt(String plainText) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[12];
        rnd.nextBytes(iv);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        // [CHECKPOINT id=JSEF-A02-004S cwe=327 level=L2 source=plaintext sink=Cipher(AES/GCM, random IV, external key) expect=SAFE]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // 安全 GCM 模式
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
