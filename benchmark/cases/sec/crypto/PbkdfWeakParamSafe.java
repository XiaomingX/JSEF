/*
 * JSEF Benchmark 安全样本 — PBKDF2 弱迭代次数（A02，CWE-916，L3）
 * SAFE 版：迭代次数 ≥ 100000 并使用随机盐。
 * 测试点：强 SAST/LLM 应识别强度参数安全而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PbkdfWeakParamSafe {

    /**
     * 安全入口：高迭代次数 + 随机盐。
     */
    static String deriveKey(String password) throws Exception {
        SecureRandom rnd = new SecureRandom();
        byte[] salt = new byte[16];
        rnd.nextBytes(salt);   // 随机盐
        // [CHECKPOINT id=JSEF-A02-003S cwe=916 level=L3 source=password sink=PBEKeySpec(iterationCount>=100000, random salt) expect=SAFE]
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);   // 足够迭代
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return Base64.getEncoder().encodeToString(f.generateSecret(spec).getEncoded());
    }
}
