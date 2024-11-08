package com.freedom.securitysamples.api.corsConfig;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CorsController {

    // 示例1 - 允许所有源
    @GetMapping("/cors/example01")
    public ResponseEntity<String> unsafeAllOrigins() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", "*");
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe all origins");
    }

    // 示例2 - 直接信任请求的Origin
    @GetMapping("/cors/example02")
    public ResponseEntity<String> unsafeOrigin(@RequestHeader("Origin") String origin) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", origin);
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe origin");
    }

    // 示例3 - 过于宽松的凭证配置
    @GetMapping("/cors/example03")
    public ResponseEntity<String> unsafeCredentials() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", "http://unsafe-site.com");
        headers.add("Access-Control-Allow-Credentials", "true");
        headers.add("Access-Control-Allow-Methods", "*");
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe credentials");
    }

    // 示例4 - 错误的通配符使用
    @GetMapping("/cors/example04")
    public ResponseEntity<String> unsafeWildcard() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", "*.example.com");
        headers.add("Access-Control-Allow-Headers", "*");
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe wildcard");
    }

    // 示例5 - 敏感操作的不当CORS配置
    @PostMapping("/cors/example05")
    public ResponseEntity<String> unsafeMethodWithCors() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", "*");
        headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        headers.add("Access-Control-Allow-Headers", "Authorization");
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe sensitive operation");
    }

    // 示例6 - 不当的预检请求配置
    @RequestMapping(value = "/cors/example06", method = RequestMethod.OPTIONS)
    public ResponseEntity<String> unsafePreflightConfig() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", "*");
        headers.add("Access-Control-Max-Age", "36000000");
        headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe preflight");
    }

    // 示例7 - 错误的多源配置
    @GetMapping("/cors/example07")
    public ResponseEntity<String> unsafeMultipleOrigins() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", "http://site1.com, http://site2.com");
        return ResponseEntity.ok()
                .headers(headers)
                .body("Response with unsafe multiple origins");
    }
}