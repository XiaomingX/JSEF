// [VULN]
package com.jsef.benchmark.vuln;

import java.security.SecureRandom;
import java.util.Random;

/**
 * JSEF-Benchmark — 子目标 B2-4：可预测随机种子 (CWE-338，难度 L2)
 *
 * ① 子目标清单：
 *    - 使用固定常量或时间戳作为 Random / SecureRandom 的种子；
 *    - 生成的序列可预测 → 令牌、IV、密钥材料可被穷举/重放。
 *
 * ② 可达性说明：
 *    不可信源为"攻击者可知的弱种子"（固定常量 FIXED_SEED 或 System.currentTimeMillis()），
 *    经 new Random(seed) / new SecureRandom(seedBytes) 进入 PRNG，
 *    数据流 seed → PRNG 构造 直连。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示"弱种子"的缺陷语义，不提供种子预测/令牌破解脚本。
 *
 * ④ 修复要点：
 *    使用无参 new SecureRandom() 由系统熵源自动播种，见 sec/PredictableSeed_Safe.java。
 */
public class PredictableSeed {

    private static final long FIXED_SEED = 123456789L;

    /**
     * 危险：Random 使用固定种子 → 输出完全可预测。
     */
    static int weakRandom() {
        Random r = new Random(FIXED_SEED);
        // [VULN] 固定种子 → 输出可预测（同类缺陷，CHECKPOINT 见下方 SecureRandom 时间戳种子）
        return r.nextInt();
    }

    /**
     * 危险：SecureRandom 用时间戳种子字节 → 仍可被预测。
     */
    static byte[] weakSecure() throws Exception {
        long t = System.currentTimeMillis();
        byte[] seedBytes = java.nio.ByteBuffer.allocate(8).putLong(t).array();
        SecureRandom sr = new SecureRandom(seedBytes);
        // [CHECKPOINT id=JSEF-SEED-001 cwe=338 level=L2 source=timestamp seed sink=new SecureRandom(seed) expect=VULN]
        byte[] out = new byte[16];
        sr.nextBytes(out);
        return out;
    }
}
