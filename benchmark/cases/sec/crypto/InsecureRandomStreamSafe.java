/*
 * JSEF Benchmark 安全样本 — 弱随机数生成令牌（A02，CWE-330，L2）
 * SAFE 版：使用 java.security.SecureRandom 生成令牌。
 * 测试点：强 SAST/LLM 应识别使用密码学安全随机数而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import java.security.SecureRandom;

public class InsecureRandomStreamSafe {

    /**
     * 安全入口：用 SecureRandom 生成令牌。
     */
    static String generateToken() {
        SecureRandom rnd = new SecureRandom();   // 密码学安全
        // [CHECKPOINT id=JSEF-A02-005S cwe=330 level=L2 source=SecureRandom instance sink=token string (unpredictable) expect=SAFE]
        return Long.toHexString(rnd.nextLong());   // 令牌不可预测
    }
}
