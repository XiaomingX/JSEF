package com.jsef.benchmark.sec;

import java.net.URI;
import java.util.Set;

/*
 * JSEF-Benchmark L2 — 前缀匹配开放重定向修复
 *
 * 修复：解析 URL 取出 host，与白名单 Set{"trusted.example"} 做精确相等匹配，
 * 而非前缀包含。这样 "trusted.example.com.evil.com" 因 host 不符而被拒绝。
 *
 * CWE-601。SAFE 侧按实现判安全。
 */
public class RedirectStartsWithSafe {

    private static final Set<String> ALLOWED_HOSTS = Set.of("trusted.example");

    /**
     * 解析 URL 校验 host 后重定向。
     *
     * @param userUrl 用户可控的重定向目标
     */
    public void redirect(String userUrl) throws Exception {
        URI uri = URI.create(userUrl);
        String host = uri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {    // 精确 host 匹配
            throw new SecurityException("untrusted redirect host");
        }
        // [CHECKPOINT id=JSEF-NV204S cwe=601 level=L2 source=userUrl sink=sendRedirect (after host whitelist check) expect=SAFE]
        sendRedirect(userUrl);
    }

    // 抽象 sink：语义等价 response.sendRedirect(userUrl)
    static void sendRedirect(String url) {
        System.out.println("[redirect] " + url);
    }

    public static void main(String[] args) throws Exception {
        new RedirectStartsWithSafe().redirect("https://trusted.example.com.evil.com/phish");
    }
}
