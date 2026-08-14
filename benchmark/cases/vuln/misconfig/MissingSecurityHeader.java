/*
 * JSEF Benchmark 样本 — 缺失安全响应头（A05，CWE-693，L2）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实点击劫持等利用。
 *
 * 知识点（A05 安全配置错误，CWE-693 防护机制失效）：
 *   响应未设置 X-Content-Type-Options、X-Frame-Options、Content-Security-Policy 等
 *   安全头，使页面易受 MIME 嗅探 / 点击劫持等攻击。属配置缺失类问题。
 */
import java.util.Map;

public class MissingSecurityHeader {

    /**
     * 危险入口：响应安全头缺失。
     */
    static Map<String, String> buildHeaders() {
        // [CHECKPOINT id=JSEF-A05-003 cwe=693 level=L2 source=response headers sink=missing X-Content-Type-Options/X-Frame-Options/CSP expect=VULN]
        return Map.of("Content-Type", "text/html");   // 缺全部安全头
    }
}
