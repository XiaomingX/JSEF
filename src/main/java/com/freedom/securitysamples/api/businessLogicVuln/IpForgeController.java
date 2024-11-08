package com.freedom.securitysamples.api.businessLogicVuln;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class IpForgeController {

    // 安全的获取方式
    @RequestMapping("/ipforge/good01")
    public String getClientIpAddress(HttpServletRequest request) {
        // 直接获取客户端IP,较难伪造
        return request.getRemoteAddr();
    }

    // 不安全的获取方式示例
    @RequestMapping("/ipforge/bad01")
    public String getIpFromXForwardedFor(HttpServletRequest request) {
        // X-Forwarded-For 头部可被轻易伪造
        String clientIp = request.getHeader("X-Forwarded-For");
        return clientIp;
    }

    @RequestMapping("/ipforge/bad02")
    public String getIpFromXRealIP(HttpServletRequest request) {
        // X-Real-IP 头部可被伪造
        String clientIp = request.getHeader("X-Real-IP");
        return clientIp;
    }

    @RequestMapping("/ipforge/bad03")
    public String getIpFromProxy(HttpServletRequest request) {
        // Proxy-Client-IP 头部可被伪造
        String clientIp = request.getHeader("Proxy-Client-IP");
        return clientIp;
    }

    @RequestMapping("/ipforge/bad04")
    public String getIpFromWLProxyClientIP(HttpServletRequest request) {
        // WL-Proxy-Client-IP 头部可被伪造
        String clientIp = request.getHeader("WL-Proxy-Client-IP");
        return clientIp;
    }

    @RequestMapping("/ipforge/bad05")
    public String getIpFromHTTPClientIP(HttpServletRequest request) {
        // HTTP_CLIENT_IP 头部可被伪造
        String clientIp = request.getHeader("HTTP_CLIENT_IP");
        return clientIp;
    }

    @RequestMapping("/ipforge/bad06")
    public String getIpFromHTTPXForwardedFor(HttpServletRequest request) {
        // HTTP_X_FORWARDED_FOR 头部可被伪造
        String clientIp = request.getHeader("HTTP_X_FORWARDED_FOR");
        return clientIp;
    }

    // 推荐的安全获取方式
    @RequestMapping("/ipforge/recommended")
    public String getIpAddressSecurely(HttpServletRequest request) {
        String ip = null;

        // 按优先级依次尝试获取
        String[] headers = {
                "X-Forwarded-For",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_CLIENT_IP",
                "HTTP_X_FORWARDED_FOR"
        };

        for (String header : headers) {
            ip = request.getHeader(header);
            if (isValidIp(ip)) {
                break;
            }
        }

        // 如果上述方法都未获取到有效IP,则使用getRemoteAddr()
        if (!isValidIp(ip)) {
            ip = request.getRemoteAddr();
        }

        // 如果是多个IP,取第一个
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0];
        }

        return ip;
    }

    // IP地址有效性检查
    private boolean isValidIp(String ip) {
        return ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip);
    }
}