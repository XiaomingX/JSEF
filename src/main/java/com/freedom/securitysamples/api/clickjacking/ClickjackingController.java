package com.freedom.securitysamples.api.clickjacking;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ClickjackingController {

    @GetMapping("/vulnerable/page")
    public String getVulnerablePage() {
        // 这个页面容易受到点击劫持攻击，因为没有设置任何防御措施
        return "<html>" +
                "<head><title>易受攻击的页面</title></head>" +
                "<body>" +
                "<h1>重要操作</h1>" +
                "<form action='/api/important-action' method='POST'>" +
                "<button type='submit'>点击这里</button>" +
                "</form>" +
                "</body>" +
                "</html>";
    }
}