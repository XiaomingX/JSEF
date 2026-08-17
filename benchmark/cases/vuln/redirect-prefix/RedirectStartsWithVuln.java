package com.jsef.benchmark.vuln;

import java.util.Set;

/*
 * JSEF-Benchmark L2 — 前缀匹配开放重定向绕过
 *
 * 难度：L2（多跳但无断点）。防护用 userUrl.startsWith("https://trusted.example/")
 * 校验，但 startsWith 不校验“完整主机”，于是 "https://trusted.example.com.evil.com"
 * 也能通过：它的开头确实是 "https://trusted.example/"，但主机实为 evil.com。
 * 攻击者借此把用户重定向到钓鱼站点。
 *
 * CWE-601 (Open Redirect)。安全底线：仅 localhost 演示语义。
 *
 * 修复要点（对照 RedirectStartsWithSafe.java）：解析 URL 取 host，做精确白名单匹配。
 */
public class RedirectStartsWithVuln {

    /**
     * 仅前缀校验后发起重定向。
     *
     * @param userUrl 用户可控的重定向目标
     */
    public void redirect(String userUrl) {
        if (userUrl.startsWith("https://trusted.example/")) {   // 仅前缀，不校验完整主机
            // [CHECKPOINT id=JSEF-NV204 cwe=601 level=L2 source=userUrl sink=sendRedirect (after startsWith prefix check) expect=VULN]
            sendRedirect(userUrl);                               // trusted.example.com.evil.com 可绕过
        }
    }

    // 抽象 sink：语义等价 response.sendRedirect(userUrl)
    static void sendRedirect(String url) {
        System.out.println("[redirect] " + url);
    }

    public static void main(String[] args) {
        new RedirectStartsWithVuln().redirect("https://trusted.example.com.evil.com/phish");
    }
}
