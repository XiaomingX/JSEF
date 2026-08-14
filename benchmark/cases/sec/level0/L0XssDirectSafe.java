package com.jsef.benchmark.sec;

import java.io.PrintWriter;

/**
 * JSEF-Benchmark L0 — L0XssDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：输出前对不可信输入做 HTML 转义，阻断脚本注入。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * CWE-79 Cross-site Scripting (Reflected)。
 */
public class L0XssDirectSafe {

    /**
     * 输出前转义：不可信输入被编码，不再作为原始 HTML 写入响应。
     *
     * @param userInput 不可信输入
     */
    public void run(PrintWriter out, String userInput) {
        String safe = escapeHtml(userInput);
        // [CHECKPOINT id=JSEF-L0-XSS-001S cwe=79 level=L0 source=userInput sink=response.getWriter().print expect=SAFE]
        out.print("<h1>Hello " + safe + "</h1>");
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }

    public static void main(String[] args) {
        new L0XssDirectSafe().run(System.out, "localhost-demo");
    }
}
