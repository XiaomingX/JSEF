package com.freedom.securitysamples.api.crossSiteScripting;

import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

@RestController
@RequestMapping("/api")
public class XssController {

    // 1. 原始的不安全示例 - 直接返回用户输入
    @GetMapping("xss/bad")
    public String getXssVulnerableResponse(@RequestParam("input") String userInput) {
        return userInput;
    }

    // 2. HTML内容直接拼接 - 不安全
    @GetMapping("xss/bad/html")
    public String getHtmlContent(@RequestParam("name") String name) {
        return "<div>Welcome, " + name + "!</div>";
    }

    // 3. JavaScript代码拼接 - 不安全
    @GetMapping("xss/bad/script")
    public String getScriptContent(@RequestParam("code") String code) {
        return "<script>" + code + "</script>";
    }

    // 4. URL参数直接嵌入 - 不安全
    @GetMapping("xss/bad/url")
    public String getUrlContent(@RequestParam("url") String url) {
        return "<a href='" + url + "'>Click here</a>";
    }

    // 5. JSON数据直接输出 - 不安全
    @GetMapping("xss/bad/json")
    public String getJsonContent(@RequestParam("data") String data) {
        return "{\"userInput\":\"" + data + "\"}";
    }

    // 6. 模板渲染中的不安全使用
    @GetMapping("xss/bad/template")
    public String getTemplateContent(Model model, @RequestParam("message") String message) {
        model.addAttribute("message", message);
        return "template"; // 假设template.html中直接使用了${message}
    }

    // 7. CSS样式注入 - 不安全
    @GetMapping("xss/bad/style")
    public String getStyleContent(@RequestParam("color") String color) {
        return "<div style='color:" + color + "'>Colored text</div>";
    }

    // 8. 图片标签属性注入 - 不安全
    @GetMapping("xss/bad/image")
    public String getImageContent(@RequestParam("src") String src) {
        return "<img src='" + src + "' />";
    }

    // 9. iframe内容注入 - 不安全
    @GetMapping("xss/bad/iframe")
    public String getIframeContent(@RequestParam("content") String content) {
        return "<iframe srcdoc='" + content + "'></iframe>";
    }

    // 10. 事件处理器注入 - 不安全
    @GetMapping("xss/bad/event")
    public String getEventContent(@RequestParam("handler") String handler) {
        return "<button onclick='" + handler + "'>Click me</button>";
    }
}