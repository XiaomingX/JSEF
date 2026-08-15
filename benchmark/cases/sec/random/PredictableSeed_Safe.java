// [VULN]
package com.jsef.benchmark.sec;

import java.security.SecureRandom;

/**
 * JSEF-Benchmark — 子目标 B2-4 安全对照：不可预测随机种子 (CWE-338，SAFE)
 *
 * ① 子目标清单：
 *    - 使用无参构造的 SecureRandom，由系统熵源自动播种；
 *    - 不向 PRNG 注入固定/时间戳种子。
 *
 * ② 可达性说明：
 *    无任何不可信/弱种子流入 PRNG，SecureRandom 由操作系统 CSPRNG 播种，
 *    输出不可预测 → 不可达种子预测类漏洞。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示安全写法，不提供任何攻击脚本。
 *
 * ④ 修复要点：
 *    无参 new SecureRandom()；如需可重现性应使用密钥派生而非裸种子。
 */
public class PredictableSeed_Safe {

    /**
     * 安全：无参 SecureRandom，系统自动播种。
     */
    static byte[] strong() {
        SecureRandom sr = new SecureRandom();
        // [CHECKPOINT id=JSEF-SEED-001S cwe=338 level=L2 source=system entropy sink=new SecureRandom() expect=SAFE]
        byte[] out = new byte[16];
        sr.nextBytes(out);
        return out;
    }
}
