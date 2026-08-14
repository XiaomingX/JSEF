/*
 * JSEF Benchmark 样本 — 不安全默认配置：默认开启 debug（VulnGym 子类 BL-INSECURE-DEFAULT，CWE-16，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"默认配置语义"——debug/verbose 模式默认开启，会在错误页与日志中泄露内部状态。
 * 数据流干净，但默认暴露面过大。静态分析需在 isDebugEnabled() 处识别"默认 true 的调试开关"。
 */
package com.jsef.benchmark.vuln;

public class DebugDefaultOn {

    // 危险：调试模式默认开启
    static final boolean DEBUG = true;

    // 危险：按默认开关输出详细内部信息
    static String renderError(Throwable t) {
        // source：运行时异常（经默认开启的 debug 开关暴露）
        // [CHECKPOINT id=JSEF-V1-DEF-002 cwe=16 level=L3 source=exception via DEBUG=true sink=response (verbose stack trace) expect=VULN]
        if (DEBUG) return org.apache.commons.lang3.exception.ExceptionUtils.getStackTrace(t);
        return "internal error";
    }
}
