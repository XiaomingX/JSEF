```java
package com.freedom.securitysamples.api.templateInjection;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class TemplateInjectionController {

    @GetMapping("/template/bad01")
    public String processTemplate(@RequestParam String userInput) {
        try {
            // 创建 FreeMarker 配置
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
            
            // 直接使用用户输入作为模板内容（这是不安全的！）
            Template template = new Template("userTemplate", 
                new StringReader(userInput), 
                cfg);

            // 准备数据模型
            Map<String, Object> dataModel = new HashMap<>();
            dataModel.put("user", "admin");
            dataModel.put("role", "administrator");

            // 处理模板
            StringWriter writer = new StringWriter();
            template.process(dataModel, writer);

            return writer.toString();

        } catch (IOException | TemplateException e) {
            return "Template processing error: " + e.getMessage();
        }
    }
}
```

这段代码存在以下安全问题：

1. 模板注入漏洞：
- 直接将用户输入作为模板内容
- 没有对用户输入进行任何验证或过滤
- 允许用户控制模板逻辑

2. 潜在的攻击场景：
   攻击者可以注入恶意的模板表达式，例如：
```
${.system["java.lang.Runtime"].getRuntime().exec("calc.exe")}
```

3. 建议的安全修复方案：
- 不要直接使用用户输入作为模板
- 使用预定义的模板文件
- 对用户输入进行严格的验证和过滤
- 限制模板的功能和访问范围
- 实施适当的访问控制

4. 安全的代码示例：
```java
@GetMapping("/template/good01")
public String processTemplateSafely(@RequestParam String userInput) {
    try {
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
        cfg.setClassForTemplateLoading(this.getClass(), "/templates");
        
        // 使用预定义的模板文件
        Template template = cfg.getTemplate("safe_template.ftl");
        
        Map<String, Object> dataModel = new HashMap<>();
        // 对用户输入进行验证和转义
        dataModel.put("userInput", escapeHtml(userInput));
        
        StringWriter writer = new StringWriter();
        template.process(dataModel, writer);
        
        return writer.toString();
    } catch (Exception e) {
        return "Error processing template";
    }
}

private String escapeHtml(String input) {
    // 实现适当的HTML转义逻辑
    return input.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
}
