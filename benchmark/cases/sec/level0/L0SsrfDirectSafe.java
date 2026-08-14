package com.jsef.benchmark.sec;

import java.net.URL;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark L0 — L0SsrfDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：仅允许预定义白名单主机/协议发起连接，拒绝任意外部 URL。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * CWE-918 Server-Side Request Forgery。
 */
public class L0SsrfDirectSafe {

    private static final List<String> ALLOWED_HOSTS = Arrays.asList("localhost", "127.0.0.1");

    /**
     * 白名单校验后连接，URL 主机必须在允许列表内。
     *
     * @param userInput 不可信输入
     */
    public void run(String userInput) throws Exception {
        URL url = new URL(userInput);
        if (!ALLOWED_HOSTS.contains(url.getHost())) {
            throw new SecurityException("ssrf blocked: host not allowed " + url.getHost());
        }
        // [CHECKPOINT id=JSEF-L0-SSRF-001S cwe=918 level=L0 source=userInput sink=URL.openConnection expect=SAFE]
        url.openConnection();
    }

    public static void main(String[] args) throws Exception {
        new L0SsrfDirectSafe().run("http://localhost:8080/demo");
    }
}
