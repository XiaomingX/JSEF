package com.jsef.benchmark.vendor;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark B6 — Juliet 式 good/bad 跨文件调用链（命令注入 CWE-78）之 good 端
 *
 * 抽象自 Juliet (NIST SAMATE) https://samate.nist.gov/SARD/ 。
 * 作为 {@link JulietStyle_CommandInjection_CrossFile} 的配对 SAFE 端：
 * 对不可信输入做白名单校验，仅允许预定义的安全命令执行（混淆样本，不应报）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class JulietStyle_CommandInjection_CrossFile_Good {

    // 白名单：仅允许这些命令（Juliet good 端的标准做法）
    private static final List<String> ALLOWED = Arrays.asList("list", "status", "version");

    /**
     * good：先白名单校验，非白名单直接拒绝，避免命令注入。
     */
    public void good(String userData) throws IOException {
        // [CHECKPOINT id=JSEF-VEND-CMD-001S cwe=78 level=L4 source=userData sink=Runtime.getRuntime().exec expect=SAFE]
        if (!ALLOWED.contains(userData)) {
            throw new IllegalArgumentException("disallowed command: " + userData);
        }
        Runtime.getRuntime().exec("ls " + userData);
    }
}
