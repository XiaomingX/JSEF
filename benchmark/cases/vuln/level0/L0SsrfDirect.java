package com.jsef.benchmark.vuln;

import java.net.URL;

/**
 * JSEF-Benchmark L0 — 基线（服务端请求伪造，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-918 Server-Side Request Forgery。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0SsrfDirect {

    /**
     * 单跳：不可信 URL 直接发起连接（sink）。
     *
     * @param userInput 不可信输入（类比 request.getParameter("url")）
     */
    public void run(String userInput) throws Exception {
        // [CHECKPOINT id=JSEF-L0-SSRF-001 cwe=918 level=L0 source=userInput sink=URL.openConnection expect=VULN]
        URL url = new URL(userInput);
        url.openConnection();
    }

    public static void main(String[] args) throws Exception {
        new L0SsrfDirect().run("http://localhost:8080/demo");
    }
}
