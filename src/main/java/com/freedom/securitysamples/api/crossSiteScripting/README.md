```java
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
```

这些示例展示了多种常见的XSS漏洞场景。主要存在以下问题：

1. **直接输出用户输入**
- 没有进行任何过滤或转义
- 可能导致任意JavaScript代码执行

2. **HTML内容拼接**
- 允许注入HTML标签
- 可能导致DOM结构被破坏

3. **JavaScript代码注入**
- 直接将用户输入嵌入script标签
- 可执行恶意JavaScript代码

4. **URL注入**
- 未验证URL的合法性
- 可能导致javascript:协议执行

5. **JSON数据注入**
- 未正确处理JSON字符串
- 可能破坏JSON结构

6. **模板注入**
- 模板中直接使用未转义的变量
- 可能导致模板注入攻击

7. **CSS注入**
- CSS属性值未经过滤
- 可能导致样式污染

8. **图片标签注入**
- src属性未经验证
- 可能加载恶意资源

9. **iframe注入**
- 直接将用户输入放入iframe
- 可能加载恶意页面

10. **事件处理器注入**
- 直接将用户输入作为事件处理器
- 可执行任意JavaScript代码

安全建议：

1. 对所有用户输入进行严格验证和过滤
2. 使用HTML转义函数处理输出内容
3. 实施内容安全策略(CSP)
4. 使用安全的模板引擎
5. 采用参数化查询避免注入
6. 实施输入长度限制
7. 使用安全的JSON序列化方法
8. 对URL进行白名单验证
9. 禁用危险的HTML标签和属性
10. 使用现代框架提供的安全机制

这些示例代码展示了各种可能的XSS漏洞场景，在实际开发中应该避免这些不安全的写法，采用适当的安全措施进行防护。