package com.jsef.benchmark.sec;

/**
 * JSEF-Benchmark Phase5-C — 错误信息泄露安全版（CWE-209，难度 L2）
 *
 * 与 ErrorBasedInfoLeak 对照：返回泛化错误文案，内部细节仅记录到服务端日志，
 * 不回传给客户端，是真正的 SAFE，用于计算 TN / 误报（FP）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实探测脚本。
 */
public class ErrorBasedInfoLeakSafe {

    static String handle(Exception e) {
        // 服务端记录细节，客户端仅见泛化信息
        System.err.println("internal error: " + e); // 仅服务端日志
        // [CHECKPOINT id=JSEF-BL-002S cwe=209 level=L2 source=exception sink=generic message to client expect=SAFE]
        return "internal server error"; // 不泄露内部细节
    }
}
