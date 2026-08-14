package com.jsef.benchmark.vuln;

import java.io.PrintWriter;

/**
 * JSEF-Benchmark L0 — 基线（反射型 XSS，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-79 Cross-site Scripting (Reflected)。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0XssDirect {

    /**
     * 单跳：不可信入参直接写入 HTTP 响应（sink）。
     *
     * @param userInput 不可信输入（类比 @RequestParam name）
     */
    public void run(PrintWriter out, String userInput) {
        // [CHECKPOINT id=JSEF-L0-XSS-001 cwe=79 level=L0 source=userInput sink=response.getWriter().print expect=VULN]
        out.print("<h1>Hello " + userInput + "</h1>");
    }

    public static void main(String[] args) {
        new L0XssDirect().run(System.out, "localhost-demo");
    }
}
