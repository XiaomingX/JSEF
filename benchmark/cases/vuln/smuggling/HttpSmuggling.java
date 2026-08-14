/*
 * JSEF Benchmark 样本 — HTTP 请求走私（CWE-444，L4）
 * 后端用 HttpClient 转发请求，前端用 Content-Length、后端用 Transfer-Encoding，
 * 直接透传含两者冲突的攻击头。
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
package com.jsef.benchmark.vuln;

public class HttpSmuggling {

    // 演示用请求/客户端接口（语义同 HttpClient）
    interface Request { void setHeader(String name, String value); }
    interface HttpClient { void send(Request req); }

    // [VULN] 前端用 CL、后端用 TE，直接透传冲突头
    static void forward(HttpClient client, String userContentLength, String userTransferEncoding) {
        Request req = null; // 占位
        // source：不可信请求头（攻击者可控的 CL 与 TE）
        // [CHECKPOINT id=JSEF-SMUGGLE-001 cwe=444 level=L4 source=attacker-controlled CL+TE headers sink=backend HttpClient.send (conflicting framing) expect=VULN]
        req.setHeader("Content-Length", userContentLength);       // 前端解释 CL
        req.setHeader("Transfer-Encoding", userTransferEncoding); // 后端解释 TE → 走私
        client.send(req);
    }
}
