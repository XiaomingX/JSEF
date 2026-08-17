package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L3 — SSRF scheme 白名单绕过（元数据/本地文件读取）
 *
 * 难度：L3（间接/跨方法语义）。服务端的防护只校验 URL 的 scheme 是否为
 * "http" 或 "https"（用 userUrl.startsWith("http") 近似判断），但漏掉了：
 *   1) file:///            —— 可读取本地文件系统任意文件
 *   2) gopher://           —— 可构造任意 TCP 协议请求，攻击内网服务
 *   3) http://169.254.169.254/ —— 云实例元数据地址（IMDS），可窃取临时
 *      凭据、IAM role、启动脚本等云凭据
 * 由于 scheme 校验通过后直接发起请求，攻击者传入上述 URL 即可越权读取
 * 本地文件或云凭据。
 *
 * CWE-918 (SSRF)。安全底线：仅 localhost 演示语义，占位类 + 模拟 sink，
 * 不引入任何真实网络库，不生成真实攻击载荷。
 *
 * 修复要点（对照 SsrfSchemeMetadataSafe.java）：scheme 严格白名单仅允许
 * http/https（非 startsWith 近似），并解析目标 IP 拒绝元数据地址
 * 169.254.169.254 与内网网段。
 */
public class SsrfSchemeMetadataVuln {

    /**
     * 取用户 URL，仅做 scheme 前缀校验后发起请求。
     *
     * @param userUrl 用户可控的目标 URL
     */
    public void fetchUserUrl(String userUrl) {
        // scheme 校验：仅判断以 "http" 开头，漏掉 file:///、gopher://、元数据 IP
        // [CHECKPOINT id=JSEF-SSM-001 cwe=918 level=L3 source=userUrl sink=UrlFetcherStub.fetch expect=VULN trace=benchmark/cases/vuln/ssrf-metadata/SsrfSchemeMetadataVuln.java:32,benchmark/cases/vuln/ssrf-metadata/SsrfSchemeMetadataVuln.java:34]
        boolean schemeOk = userUrl.startsWith("http");   // 仅前缀，不校验完整 scheme 白名单
        if (schemeOk) {
            UrlFetcherStub.fetch(userUrl);               // 可传入 file:///、gopher://、169.254.169.254
        }
    }

    /**
     * 抽象 sink：语义等价 new URL(url).openConnection().getInputStream()，
     * 仅 localhost 演示语义 —— 实际仅打印请求目标，不发起真实连接。
     */
    static class UrlFetcherStub {
        // 语义等价：new URL(url).openConnection()
        static void fetch(String url) {
            System.out.println("[fetch] " + url);
        }
    }

    public static void main(String[] args) {
        new SsrfSchemeMetadataVuln().fetchUserUrl("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    }
}
