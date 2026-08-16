/*
 * JSEF Benchmark 样本 — 弱随机安全对照 (CWE-330, L1/L2)
 * 使用 SecureRandom 生成令牌与验证码。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.security.SecureRandom;

public class WeakRandomSafe {

    private static final SecureRandom SR = new SecureRandom();

    static String genToken() {
        byte[] buf = new byte[16];
        SR.nextBytes(buf); // [CHECKPOINT id=JSEF-EXT-007S cwe=330 level=L1 source=SecureRandom sink=SecureRandom.nextBytes token generation expect=SAFE]
        StringBuilder sb = new StringBuilder();
        for (byte b : buf) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static String genCaptcha() {
        StringBuilder sb = new StringBuilder(); // [CHECKPOINT id=JSEF-EXT-008S cwe=330 level=L2 source=SecureRandom sink=SecureRandom.nextInt captcha generation expect=SAFE]
        for (int i = 0; i < 6; i++) sb.append(SR.nextInt(10));
        return sb.toString();
    }
}
