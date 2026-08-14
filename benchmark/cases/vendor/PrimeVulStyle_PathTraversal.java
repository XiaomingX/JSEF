package com.jsef.benchmark.vendor;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import jakarta.servlet.http.HttpServletRequest;

/**
 * JSEF-Benchmark B6 — PrimeVul / CVEfixes 风格路径穿越（CWE-22）
 *
 * 抽象自 PrimeVul https://arxiv.org/abs/2403.18624 与 CVEfixes
 * https://github.com/secureIT-project/CVEfixes 。二者以真实 CVE + 修复对照、
 * 高质协商标注著称（PrimeVul 用协商标注解决标签噪声）。
 *
 * 本文件提供 VULN 版：直接用 request.getParameter("file") 拼路径打开文件，未校验，
 * 攻击者可传入 "../../../etc/passwd" 实施路径穿越（L2 多跳，CAP-04/08）。
 * 对应的 SAFE 版见 {@link PrimeVulStyle_PathTraversalSafe}。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 * 引用框架类说明：演示用 jakarta.servlet.http.HttpServletRequest，仅作 source 语义标注，
 * 样本用于静态分析/LLM 阅读，不强求编译。
 */
public class PrimeVulStyle_PathTraversal {

    private static final String BASE_DIR = "/var/jsef/uploads";

    /**
     * VULN：未校验的用户输入直接拼入路径。
     */
    public void readVuln(HttpServletRequest request) throws IOException {
        String fileName = request.getParameter("file");
        // [CHECKPOINT id=JSEF-VEND-PT-001 cwe=22 level=L2 source=request.getParameter("file") sink=new FileInputStream expect=VULN]
        FileInputStream fis = new FileInputStream(BASE_DIR + "/" + fileName);
        fis.close();
    }
}
