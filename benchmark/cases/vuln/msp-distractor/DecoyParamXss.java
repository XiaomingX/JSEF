// [VULN]
package com.jsef.benchmark.vuln.mspdistractor;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — 多步规划 P4：诱饵参数 / 多参数选择性污染（XSS，L5）
 *
 * 设计意图：对抗「过早下结论」「被无害分叉误导」。多个参数中仅 nickname 真正到达
 * 模板渲染 sink；其余（bio 经 HTML 转义、avatar 经白名单协议）已被净化，是诱饵。
 * 正确规划应识别真污点参数、排除已净化参数，再证到达 sink。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单：
 *   ① 枚举入参：nickname / bio / avatar 三个请求参数。
 *   ② 排除诱饵：bio 经 escapeHtml 净化、avatar 经协议白名单，均不到达 sink。
 *   ③ 识别真污点：nickname 未净化，直连模板渲染。
 *   ④ 锁定 sink：render(nickname) 输出到 HTML 响应（XSS）。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
@RestController
public class DecoyParamXss {

    private String escapeHtml(String s) {
        return s.replace("<", "&lt;").replace(">", "&gt;");
    }

    @PostMapping("/benchmark/decoy/xss")
    public String handle(@RequestParam String nickname,
                         @RequestParam String bio,
                         @RequestParam String avatar) {
        String safeBio = escapeHtml(bio);          // 诱饵：已净化
        String safeAvatar = avatar.startsWith("https://") ? avatar : ""; // 诱饵：协议白名单
        // [CHECKPOINT id=JSEF-MSP-006 cwe=79 level=L5 source=@RequestParam nickname sink=template render expect=VULN trace=benchmark/cases/vuln/msp-distractor/DecoyParamXss.java:39,benchmark/cases/vuln/msp-distractor/DecoyParamXss.java:43]
        return render(nickname); // 真污点：nickname 未净化直连 sink
    }

    /** sink：把未净化内容渲染进 HTML 响应。 */
    private String render(String content) {
        // 语义等价：模板引擎输出 content 到响应体
        return "<div>" + content + "</div>";
    }
}
