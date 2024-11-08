我来帮您分析CORS漏洞相关的常见错误配置,并提供更多的示例代码。以下是一个包含多个CORS配置错误示例的完整代码:

```java
package com.freedom.securitysamples.api.corsConfig;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
public class CorsController {

    // 原始示例 - 允许所有源
    @GetMapping("/cors/example01")
    public void configureCorsHeaders(ServerHttpResponse response){
        response.getHeaders().add("Access-Control-Allow-Origin", "*");
    }

    // 错误示例1 - 直接从请求中获取Origin并设置为允许源
    @GetMapping("/cors/example02")
    public ResponseEntity<?> unsafeOrigin(@RequestHeader("Origin") String origin) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", origin); // 不安全:直接信任请求的Origin
        return ResponseEntity.ok().headers(headers).body("Response with unsafe origin");
    }

    // 错误示例2 - 过于宽松的凭证配置
    @GetMapping("/cors/example03")
    public void unsafeCredentials(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "http://unsafe-site.com");
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "*"); // 允许所有方法
    }

    // 错误示例3 - 不当的通配符使用
    @GetMapping("/cors/example04")
    public void unsafeWildcard(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*.example.com"); // 错误的通配符用法
        response.setHeader("Access-Control-Allow-Headers", "*");
    }

    // 错误示例4 - 敏感操作的不当CORS配置
    @PostMapping("/cors/example05")
    public void unsafeMethodWithCors(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        response.setHeader("Access-Control-Allow-Headers", "Authorization");
    }

    // 错误示例5 - 不当的预检请求配置
    @Options("/cors/example06")
    public void unsafePreflightConfig(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Max-Age", "36000000"); // 过长的预检有效期
        response.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
    }

    // 错误示例6 - 错误的多源配置
    @GetMapping("/cors/example07")
    public void unsafeMultipleOrigins(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "http://site1.com, http://site2.com"); // 错误的多源配置
    }
}
```

以上代码展示了几种常见的CORS配置错误:

## 主要安全问题说明

1. **不安全的Origin配置**
- 直接信任请求头中的Origin
- 使用通配符允许所有源
- 错误的多源配置语法

2. **过于宽松的凭证配置**
- 同时设置允许所有源和允许携带凭证
- 不必要地启用凭证支持

3. **不当的请求方法配置**
- 允许所有HTTP方法
- 对敏感操作启用过于宽松的CORS

4. **预检请求配置问题**
- 过长的预检有效期
- 过于宽松的请求头配置

## 安全建议

1. 应该明确指定允许的源,避免使用通配符
2. 谨慎处理需要携带凭证的请求
3. 只允许必要的HTTP方法
4. 合理设置预检请求的有效期
5. 对敏感操作采用更严格的CORS策略
6. 建议使用Spring Security提供的CORS配置机制

这些示例代码展示了各种不安全的CORS配置,可以帮助开发人员识别和避免类似的安全问题。在实际应用中应该根据具体需求采用更安全的配置方式。