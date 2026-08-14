/*
 * JSEF Benchmark 样本 — PBKDF2 弱迭代次数（A02，CWE-916，L3）
 * 运行态需 JSEF 依赖（javax.crypto）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实暴力破解脚本。
 *
 * 知识点（A02 加密缺陷，CWE-916 弱口令哈希迭代不足）：
 *   PBKDF2 迭代次数过低（如 1000），对抗暴力破解的成本不足，等价于弱哈希。
 *   污点：口令 → PBEKeySpec(iterationCount=1000) → 派生密钥。
 */
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PbkdfWeakParam {

    /**
     * 危险入口：PBKDF2 迭代次数过低。
     */
    static String deriveKey(String password) throws Exception {
        byte[] salt = "static-salt-1234".getBytes();   // 同时固定盐，更弱
        // [CHECKPOINT id=JSEF-A02-003 cwe=916 level=L3 source=password sink=PBEKeySpec(iterationCount=1000) expect=VULN]
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);   // 迭代过低
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return Base64.getEncoder().encodeToString(f.generateSecret(spec).getEncoded());
    }
}
