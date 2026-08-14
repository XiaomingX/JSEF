package com.jsef.benchmark.vendor;

import java.io.IOException;

/**
 * JSEF-Benchmark B6 — Juliet 式 good/bad 跨文件调用链（命令注入 CWE-78）
 *
 * 抽象自 Juliet (NIST SAMATE) https://samate.nist.gov/SARD/ ，CWE 命名如
 * CWE78_OS_Command_Injection__...。Juliet 以 good/bad 配对跨文件调用链著称。
 *
 * 本文件为 bad 端：直接把不可信 userData 传给 Runtime.exec（VULN，L4 跨文件）。
 * 对应的 good 端见 {@link JulietStyle_CommandInjection_CrossFile_Good}（白名单校验后执行，SAFE）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 * 引用框架类说明：自包含 Java 源码，仅用标准库 Runtime.exec，不依赖 JSEF src/main。
 */
public class JulietStyle_CommandInjection_CrossFile {

    /**
     * bad sink：不可信 userData 直接进入命令执行。
     */
    public void bad(String userData) throws IOException {
        // [CHECKPOINT id=JSEF-VEND-CMD-001 cwe=78 level=L4 source=userData sink=Runtime.getRuntime().exec expect=VULN]
        String command = "ls " + userData;
        Runtime.getRuntime().exec(command);
    }
}
