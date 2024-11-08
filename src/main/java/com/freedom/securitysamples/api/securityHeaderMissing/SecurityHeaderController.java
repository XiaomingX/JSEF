package com.freedom.securitysamples.api.securityHeaderMissing;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/security-header-missing")
public class SecurityHeaderController {

    @GetMapping("/headers/unsafe")
    public ResponseEntity<String> unsafeResponse() {
        // 直接返回响应,没有设置任何安全响应头
        return ResponseEntity.ok()
                .body("{'status':'success','data':'sensitive information'}");
    }

    @GetMapping("/cookie/unsafe")
    public ResponseEntity<String> unsafeCookie() {
        // 不安全的Cookie设置,缺少安全属性
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, "sessionId=123456")
                .body("Cookie set without security attributes");
    }

    @PostMapping("/cors/unsafe")
    public ResponseEntity<String> unsafeCors() {
        // 不安全的CORS配置,没有适当的访问控制
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body("Unsafe CORS configuration");
    }

    @GetMapping("/cache/unsafe")
    public ResponseEntity<String> unsafeCache() {
        // 没有设置缓存控制头,可能导致敏感信息被缓存
        return ResponseEntity.ok()
                .body("Sensitive data without cache control");
    }

    @GetMapping("/download/unsafe")
    public ResponseEntity<String> unsafeDownload() {
        // 不安全的文件下载配置,缺少内容处置头
        return ResponseEntity.ok()
                .body("File content without proper Content-Disposition");
    }

    @GetMapping("/referrer/unsafe")
    public ResponseEntity<String> unsafeReferrer() {
        // 缺少Referrer-Policy头,可能泄露敏感URL信息
        return ResponseEntity.ok()
                .body("Response without Referrer-Policy");
    }

    @GetMapping("/permissions/unsafe")
    public ResponseEntity<String> unsafePermissions() {
        // 缺少Permissions-Policy头,未限制浏览器功能
        return ResponseEntity.ok()
                .body("Response without Permissions-Policy");
    }

    @GetMapping("/contenttype/unsafe")
    public ResponseEntity<String> unsafeContentType() {
        // 没有明确指定Content-Type,可能导致内容类型混淆
        return ResponseEntity.ok()
                .body("<script>alert('XSS')</script>");
    }

    @GetMapping("/exposed-headers/unsafe")
    public ResponseEntity<String> unsafeExposedHeaders() {
        // 过度暴露响应头信息
        return ResponseEntity.ok()
                .header("Server", "Apache/2.4.1")
                .header("X-Powered-By", "PHP/7.4.0")
                .body("Exposed sensitive server information");
    }

    @GetMapping("/auth/unsafe")
    public ResponseEntity<String> unsafeAuthentication() {
        // 在响应头中暴露认证信息
        return ResponseEntity.ok()
                .header("Authorization", "Bearer token123")
                .body("Exposed authentication information");
    }

    /*
    这段代码存在以下安全隐患:
    1. 没有设置 X-Content-Type-Options 头,可能导致MIME类型嗅探攻击
    2. 没有设置 X-Frame-Options 头,存在点击劫持风险
    3. 没有设置 X-XSS-Protection 头,容易遭受XSS攻击
    4. 没有设置 Strict-Transport-Security 头,存在降级攻击风险
    5. 没有设置 Content-Security-Policy 头,缺乏内容安全策略
    6. Cookie没有设置 Secure、HttpOnly、SameSite 属性
    7. 不恰当的CORS配置可能导致跨域安全问题
    8. 缺少缓存控制头可能导致敏感信息被缓存
    9. 下载文件时缺少适当的Content-Disposition头
    10. 缺少Referrer-Policy可能泄露敏感URL信息
    11. 缺少Permissions-Policy无法限制浏览器功能
    12. 未指定Content-Type可能导致内容类型混淆
    13. 过度暴露服务器信息在响应头中
    14. 在响应头中暴露敏感的认证信息
    */
}