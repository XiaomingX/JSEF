package com.freedom.securitysamples.api.headerInjection;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class HeaderInjectionController {

    // 原有的不安全实现
    @GetMapping("/header/unsafe")
    public ResponseEntity<String> unsafeHeader(@RequestParam String userInput) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Custom-Header", userInput);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Response with potentially injected header");
    }

    // 原有的不安全重定向
    @GetMapping("/redirect/unsafe")
    public ResponseEntity<String> unsafeRedirect(@RequestParam String redirectUrl) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Location", redirectUrl);
        return ResponseEntity
                .status(302)
                .headers(headers)
                .body("Redirecting...");
    }

    // 原有的不安全Cookie设置
    @GetMapping("/cookie/unsafe")
    public ResponseEntity<String> unsafeCookie(@RequestParam String cookieValue) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Set-Cookie", "userdata=" + cookieValue);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Cookie set");
    }

    // 新增：不安全的Content-Disposition头部设置
    @GetMapping("/download/unsafe")
    public ResponseEntity<String> unsafeDownload(@RequestParam String fileName) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=" + fileName);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Downloading file...");
    }

    // 新增：不安全的Content-Type设置
    @GetMapping("/content-type/unsafe")
    public ResponseEntity<String> unsafeContentType(@RequestParam String contentType) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", contentType);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Content with custom type");
    }

    // 新增：不安全的Access-Control-Allow-Origin设置
    @GetMapping("/cors/unsafe")
    public ResponseEntity<String> unsafeCors(@RequestParam String origin) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Allow-Origin", origin);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("CORS enabled response");
    }

    // 新增：不安全的WWW-Authenticate头部设置
    @GetMapping("/auth/unsafe")
    public ResponseEntity<String> unsafeAuth(@RequestParam String realm) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
        return ResponseEntity
                .status(401)
                .headers(headers)
                .body("Authentication required");
    }

    // 新增：不安全的Refresh头部设置
    @GetMapping("/refresh/unsafe")
    public ResponseEntity<String> unsafeRefresh(@RequestParam String refreshUrl) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Refresh", "5; url=" + refreshUrl);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Page will refresh...");
    }

    // 新增：不安全的X-Frame-Options设置
    @GetMapping("/frame-options/unsafe")
    public ResponseEntity<String> unsafeFrameOptions(@RequestParam String frameOption) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Frame-Options", frameOption);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Frame options set");
    }

    // 新增：不安全的多Header组合设置
    @GetMapping("/multiple-headers/unsafe")
    public ResponseEntity<String> unsafeMultipleHeaders(
            @RequestParam String customHeader,
            @RequestParam String cacheControl) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Custom-Header", customHeader);
        headers.add("Cache-Control", cacheControl);
        return ResponseEntity
                .ok()
                .headers(headers)
                .body("Multiple headers set");
    }
}