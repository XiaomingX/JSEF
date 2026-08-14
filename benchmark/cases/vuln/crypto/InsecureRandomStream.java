/*
 * JSEF Benchmark 样本 — 弱随机数生成令牌（A02，CWE-330，L2）
 * 运行态需 JSEF 依赖（java.util）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实令牌预测利用。
 *
 * 知识点（A02 加密缺陷，CWE-330 随机数不足够）：
 *   java.util.Random 为可预测的线性同余发生器，用于生成会话/重置令牌可被预测。
 *   应使用 java.security.SecureRandom。污点：Random → 令牌字符串。
 */
import java.util.Random;

public class InsecureRandomStream {

    /**
     * 危险入口：用 Random 生成安全令牌。
     */
    static String generateToken() {
        Random rnd = new Random();   // 可预测
        // [CHECKPOINT id=JSEF-A02-005 cwe=330 level=L2 source=Random instance sink=token string (predictable) expect=VULN]
        return Long.toHexString(rnd.nextLong());   // 令牌可预测 → 可伪造
    }
}
