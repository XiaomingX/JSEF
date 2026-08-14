package com.jsef.benchmark.vendor;

import java.security.SecureRandom;
import java.util.Random;

/**
 * JSEF-Benchmark B6 — OWASP 式弱随机混淆（CWE-330）
 *
 * 抽象自 OWASP Benchmark https://github.com/OWASP-Benchmark/BenchmarkJava 。
 * CWE-330 关注可预测的弱随机数（用于 token / sessionId 等安全敏感场景）。
 *
 * 本文件提供一对紧邻方法：VULN 用 java.util.Random 生成 token（可预测），
 * SAFE 用 java.security.SecureRandom（密码学安全）。难度：L1（混淆类）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实利用脚本。
 */
public class OwaspStyle_WeakRandom {

    /**
     * VULN：用 java.util.Random 生成安全敏感 token（可预测，弱随机）。
     */
    public String weakToken() {
        Random rng = new Random();
        // [CHECKPOINT id=JSEF-VEND-RND-001 cwe=330 level=L1 source=Random.nextInt sink=String(concat) expect=VULN]
        return "tok-" + rng.nextInt(1_000_000);
    }

    /**
     * SAFE：用 SecureRandom 生成 token（加密强度随机，混淆样本，不应报）。
     */
    public String strongToken() {
        SecureRandom rng = new SecureRandom();
        // [CHECKPOINT id=JSEF-VEND-RND-001S cwe=330 level=L1 source=SecureRandom.nextInt sink=String(concat) expect=SAFE]
        return "tok-" + rng.nextInt(1_000_000);
    }
}
