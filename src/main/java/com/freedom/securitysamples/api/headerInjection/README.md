```java
package com.freedom.securitysamples.api.headerInjection;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HeaderInjectionController {

    // 不安全的实现 - 存在 HTTP 头注入漏洞
    @GetMapping("/header/unsafe")
    public ResponseEntity<String> unsafeHeader(@RequestParam String userInput) {
        HttpHeaders headers = new HttpHeaders();
        
        // 直接将用户输入添加到响应头中，没有进行任何验证和过滤
        headers.add("X-Custom-Header", userInput);
        
        // 创建包含可能被注入的响应头的响应
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Response with potentially injected header");
    }

    // 另一个不安全的示例 - 允许用户控制 Location 头
    @GetMapping("/redirect/unsafe")
    public ResponseEntity<String> unsafeRedirect(@RequestParam String redirectUrl) {
        HttpHeaders headers = new HttpHeaders();
        
        // 直接使用用户输入作为重定向URL，没有验证
        headers.add("Location", redirectUrl);
        
        return ResponseEntity
                .status(302)
                .headers(headers)
                .body("Redirecting...");
    }

    // 不安全的 Cookie 设置示例
    @GetMapping("/cookie/unsafe")
    public ResponseEntity<String> unsafeCookie(@RequestParam String cookieValue) {
        HttpHeaders headers = new HttpHeaders();
        
        // 直接将用户输入添加到 Cookie 中，没有进行清理
        headers.add("Set-Cookie", "userdata=" + cookieValue);
        
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Cookie set");
    }
}
```

这个示例代码展示了几种常见的 HTTP 头注入漏洞：

1. **自定义头注入**：
    - 在 `/header/unsafe` 端点中，直接将用户输入添加到响应头中
    - 攻击者可以注入换行符 (\r\n) 来添加额外的 HTTP 头或分割响应

2. **不安全的重定向**：
    - 在 `/redirect/unsafe` 端点中，直接使用用户输入作为重定向 URL
    - 攻击者可以注入恶意 URL 或操纵响应头

3. **不安全的 Cookie 设置**：
    - 在 `/cookie/unsafe` 端点中，直接将用户输入添加到 Cookie 中
    - 攻击者可以注入额外的 Cookie 参数或操纵现有 Cookie

攻击者可能的利用方式：
```
// 示例攻击输入
userInput = "valid value\r\nX-Injected-Header: malicious value"
redirectUrl = "http://evil.com\r\nX-Injected-Header: malicious value"
cookieValue = "normal value\r\nX-Injected-Header: malicious value"
```

为了修复这些漏洞，应该：
1. 验证和过滤用户输入
2. 移除或转义特殊字符（如 \r\n）
3. 使用安全的 API 来设置响应头
4. 实施适当的输入验证和 URL 白名单