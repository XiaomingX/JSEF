package com.freedom.securitysamples.api.securityHeaderMissing;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 安全响应头缺失漏洞示例控制器
 * 说明：HTTP响应头是web安全的重要防线，缺失关键安全头会导致多种攻击风险
 * 核心安全头作用：
 * - 防御XSS攻击：Content-Security-Policy、X-XSS-Protection
 * - 防御点击劫持：X-Frame-Options
 * - 防御MIME类型混淆：X-Content-Type-Options
 * - 强化传输安全：Strict-Transport-Security
 * - 控制跨域访问：Access-Control-* 系列头
 * - 保护Cookie安全：Secure、HttpOnly、SameSite等属性
 */
@RestController
@RequestMapping("/security-example/headers/missing")
public class SecurityHeaderMissingController {

    /**
     * 不安全示例1：缺失核心安全响应头
     * 漏洞点：未设置任何防御性安全头（如X-Frame-Options、Content-Security-Policy等）
     * 风险：可能遭受XSS、点击劫持、MIME类型嗅探等多种攻击
     * 修复建议：添加基础安全头集合
     * - X-Frame-Options: DENY
     * - X-Content-Type-Options: nosniff
     * - X-XSS-Protection: 1; mode=block
     * - Content-Security-Policy: 限制资源加载来源
     */
    @GetMapping("/core-headers")
    public ResponseEntity<String> missingCoreSecurityHeaders() {
        // 危险实践：仅返回业务数据，无任何安全防御头
        return ResponseEntity.ok()
                .body("{\"status\":\"success\",\"data\":\"包含用户敏感信息的响应内容\"}");
    }

    /**
     * 不安全示例2：Cookie缺失安全属性
     * 漏洞点：SessionID等Cookie未设置Secure、HttpOnly、SameSite属性
     * 风险：
     * - 无HttpOnly：可能被XSS攻击窃取Cookie
     * - 无Secure：Cookie可能通过HTTP明文传输被拦截
     * - 无SameSite：可能遭受CSRF攻击
     * 修复建议：Set-Cookie: sessionId=123456; HttpOnly; Secure; SameSite=Strict
     */
    @GetMapping("/cookie-attributes")
    public ResponseEntity<String> cookieWithoutSecurityAttributes() {
        // 危险实践：Cookie未设置安全属性
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, "sessionId=123456; Max-Age=3600")
                .body("会话Cookie已设置，但缺少安全属性");
    }

    /**
     * 不安全示例3：CORS配置过度宽松
     * 漏洞点：Access-Control-Allow-Origin设置为"*"（允许所有域名跨域访问）
     * 风险：恶意网站可通过跨域请求获取敏感数据（配合 credentials 滥用）
     * 修复建议：严格限制允许的源域名，如 Access-Control-Allow-Origin: https://trusted-domain.com
     */
    @PostMapping("/cors-configuration")
    public ResponseEntity<String> unsafeCorsConfiguration() {
        // 危险实践：允许所有来源跨域访问
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Credentials", "true") // 与*同时使用时风险加倍
                .body("跨域配置过度宽松，存在数据泄露风险");
    }

    /**
     * 不安全示例4：缺失缓存控制头
     * 漏洞点：未设置Cache-Control、Pragma等缓存控制头
     * 风险：包含敏感信息的响应可能被浏览器、代理服务器缓存，导致信息泄露
     * 修复建议：添加 Cache-Control: no-store, no-cache; Pragma: no-cache
     */
    @GetMapping("/cache-control")
    public ResponseEntity<String> missingCacheControlHeaders() {
        // 危险实践：敏感数据响应未限制缓存
        return ResponseEntity.ok()
                .body("用户身份证号：110101XXXXXXXX1234（此敏感信息可能被缓存）");
    }

    /**
     * 不安全示例5：文件下载缺失Content-Disposition头
     * 漏洞点：未指定Content-Disposition头控制文件处理方式
     * 风险：可能导致浏览器将下载内容解析为HTML/脚本，触发XSS攻击
     * 修复建议：添加 Content-Disposition: attachment; filename="safe-file.txt"
     */
    @GetMapping("/file-download")
    public ResponseEntity<String> missingContentDisposition() {
        // 危险实践：下载内容未指定处置方式，可能被浏览器误解析
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "text/plain")
                .body("<script>alert('恶意代码可能被执行')</script>");
    }

    /**
     * 不安全示例6：缺失Referrer-Policy头
     * 漏洞点：未限制Referrer信息发送策略
     * 风险：用户从敏感页面跳转时，完整URL可能泄露给第三方网站
     * 修复建议：添加 Referrer-Policy: strict-origin-when-cross-origin
     */
    @GetMapping("/referrer-policy")
    public ResponseEntity<String> missingReferrerPolicy() {
        // 危险实践：未控制Referrer信息，可能泄露敏感URL路径
        return ResponseEntity.ok()
                .body("从该页面跳转时，完整URL可能被发送到第三方网站");
    }

    /**
     * 不安全示例7：缺失Permissions-Policy头
     * 漏洞点：未限制浏览器功能（如摄像头、麦克风、地理位置等）
     * 风险：网站可能被滥用获取用户敏感设备权限
     * 修复建议：添加 Permissions-Policy: camera=(), microphone=(), geolocation=()
     */
    @GetMapping("/permissions-policy")
    public ResponseEntity<String> missingPermissionsPolicy() {
        // 危险实践：未限制浏览器功能权限，可能被滥用
        return ResponseEntity.ok()
                .body("未限制浏览器功能，可能导致不必要的设备权限被请求");
    }

    /**
     * 不安全示例8：未明确指定Content-Type头
     * 漏洞点：缺失Content-Type或未设置charset，可能导致MIME类型嗅探
     * 风险：浏览器可能将文本内容解析为HTML，触发XSS攻击
     * 修复建议：明确指定 Content-Type: text/html; charset=UTF-8 或对应类型
     */
    @GetMapping("/content-type")
    public ResponseEntity<String> missingContentTypeSpecification() {
        // 危险实践：未指定内容类型，可能被浏览器错误解析
        return ResponseEntity.ok()
                .body("<script>alert('XSS攻击可能成功')</script>");
    }

    /**
     * 不安全示例9：响应头暴露服务器敏感信息
     * 漏洞点：Server、X-Powered-By等头泄露服务器版本、技术栈信息
     * 风险：攻击者可针对性利用已知漏洞发起攻击
     * 修复建议：移除或修改这些头，如 Server: WebServer; X-Powered-By: 隐藏
     */
    @GetMapping("/exposed-server-info")
    public ResponseEntity<String> exposedServerDetailsInHeaders() {
        // 危险实践：暴露服务器版本和技术栈信息
        return ResponseEntity.ok()
                .header("Server", "Apache/2.4.1 (Unix)")
                .header("X-Powered-By", "PHP/7.4.0; Spring Boot/2.2.6")
                .body("响应头泄露了服务器技术细节，增加攻击面");
    }

    /**
     * 不安全示例10：响应头暴露认证凭证
     * 漏洞点：Authorization等头包含敏感认证信息（如Token）
     * 风险：认证凭证可能被日志记录、代理服务器缓存或未授权用户获取
     * 修复建议：不在响应头中返回认证信息，敏感数据通过请求头传输
     */
    @GetMapping("/exposed-auth-credentials")
    public ResponseEntity<String> exposedAuthenticationInHeaders() {
        // 危险实践：在响应头中返回认证Token
        return ResponseEntity.ok()
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
                .body("响应头包含敏感认证信息，存在泄露风险");
    }
}
    