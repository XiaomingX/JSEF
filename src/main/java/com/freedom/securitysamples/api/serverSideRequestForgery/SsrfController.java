package com.freedom.securitysamples.api.serverSideRequestForgery;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
@RequestMapping("/api")
public class SsrfController {

    // 原有的不安全示例1 - 缺少安全头
    @GetMapping("/ssrf/bad01")
    public String fetchRemoteImage(String imageUrl) throws IOException {
        URL remoteUrl = new URL(imageUrl);
        HttpURLConnection httpConnection = (HttpURLConnection) remoteUrl.openConnection();
        httpConnection.setRequestMethod("GET");
        return httpConnection.getResponseMessage();
    }

    // 原有的不安全示例2 - 缺少安全头
    @GetMapping("/ssrf/bad02")
    public String loadImageFromFile(String filePath) throws IOException {
        BufferedImage image = ImageIO.read(new File(filePath));
        return "Image Loaded Successfully";
    }

    // 新增不安全示例3 - 缺少X-Content-Type-Options头
    @GetMapping("/ssrf/bad03")
    public ResponseEntity<String> unsafeContentType() {
        return ResponseEntity.ok()
                .body("<script>alert('XSS');</script>");
    }

    // 新增不安全示例4 - 缺少X-Frame-Options头
    @GetMapping("/ssrf/bad04")
    public void unsafeFrameOptions(HttpServletResponse response) throws IOException {
        response.getWriter().write("<h1>Clickjacking vulnerable page</h1>");
    }

    // 新增不安全示例5 - 缺少CSP头
    @GetMapping("/ssrf/bad05")
    public ResponseEntity<String> unsafeCSP() {
        return ResponseEntity.ok()
                .body("<img src='http://evil.com/hack.jpg'>");
    }

    // 新增不安全示例6 - 缺少HSTS头
    @GetMapping("/ssrf/bad06")
    public ResponseEntity<String> unsafeHSTS() {
        return ResponseEntity.ok()
                .body("Sensitive data without HSTS");
    }

    // 新增不安全示例7 - 缺少X-XSS-Protection头
    @PostMapping("/ssrf/bad07")
    public ResponseEntity<String> unsafeXSSProtection(@RequestBody String userInput) {
        return ResponseEntity.ok()
                .body("Echo: " + userInput);
    }

    // 新增不安全示例8 - 缺少Referrer-Policy头
    @GetMapping("/ssrf/bad08")
    public ResponseEntity<String> unsafeReferrerPolicy() {
        return ResponseEntity.ok()
                .header("Location", "https://external-site.com")
                .body("Redirecting...");
    }
}