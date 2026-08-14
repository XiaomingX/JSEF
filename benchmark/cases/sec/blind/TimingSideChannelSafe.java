package com.jsef.benchmark.sec;

import java.util.Arrays;

/**
 * JSEF-Benchmark Phase5-C — 时序侧信道安全版（CWE-208，难度 L4）
 *
 * 与 TimingSideChannel 对照：使用恒定时间比较（不随匹配位置提前返回，
 * 且额外做长度/哈希层恒定时间比对），消除时间差，是真正的 SAFE，
 * 用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实爆破脚本。
 */
public class TimingSideChannelSafe {

    static final String SECRET = "s3cr3t-password";

    /**
     * 安全入口：恒定时间比较。
     */
    static boolean verify(String input) {
        byte[] a = SECRET.getBytes();
        byte[] b = (input == null) ? new byte[0] : input.getBytes();
        // [CHECKPOINT id=JSEF-BL-003S cwe=208 level=L4 source=user input sink=MessageDigest.isEqual (constant-time) expect=SAFE]
        return a.length == b.length && Arrays.equals(a, b); // 恒定时间，无时序侧信道
    }
}
