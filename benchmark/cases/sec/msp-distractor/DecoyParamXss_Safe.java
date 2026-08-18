// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.mspdistractor;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — 多步规划 P4 安全对照 (难度 L5, CWE-79, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 DecoyParamXss）：
 *   所有参数（含 nickname）统一经 escapeHtml 净化后再渲染，无可达 XSS。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
@RestController
public class DecoyParamXss_Safe {

    private String escapeHtml(String s) {
        return s.replace("<", "&lt;").replace(">", "&gt;");
    }

    @PostMapping("/benchmark/decoy/xss/safe")
    public String handle(@RequestParam String nickname,
                         @RequestParam String bio,
                         @RequestParam String avatar) {
        String safeNick = escapeHtml(nickname);
        String safeBio = escapeHtml(bio);
        String safeAvatar = avatar.startsWith("https://") ? avatar : "";
        // [CHECKPOINT id=JSEF-MSP-006S cwe=79 level=L5 source=@RequestParam nickname sink=escapeHtml reject expect=SAFE]
        return render(safeNick + safeBio + safeAvatar);
    }

    private String render(String content) {
        return "<div>" + content + "</div>";
    }
}
