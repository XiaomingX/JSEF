package com.freedom.securitysamples.api.templateInjection;

import org.springframework.web.bind.annotation.*;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.StringTemplateResolver;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import freemarker.core.TemplateClassResolver;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@RestController
@RequestMapping("/api")
public class TemplateInjectionController {

    // 1. 原始的不安全FreeMarker示例
    @GetMapping("/template/bad01")
    public String processTemplate(@RequestParam String userInput) {
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
            Template template = new Template("userTemplate",
                    new StringReader(userInput),
                    cfg);

            Map<String, Object> dataModel = new HashMap<>();
            dataModel.put("user", "admin");
            dataModel.put("role", "administrator");

            StringWriter writer = new StringWriter();
            template.process(dataModel, writer);

            return writer.toString();

        } catch (IOException | TemplateException e) {
            return "Template processing error: " + e.getMessage();
        }
    }

    // 2. 不安全的Thymeleaf模板处理
    @GetMapping("/template/bad02")
    public String processThymeleafTemplate(@RequestParam String userInput) {
        TemplateEngine templateEngine = new TemplateEngine();
        StringTemplateResolver templateResolver = new StringTemplateResolver();
        templateEngine.setTemplateResolver(templateResolver);

        Context context = new Context();
        context.setVariable("user", "admin");

        // 直接使用用户输入作为模板内容
        return templateEngine.process(userInput, context);
    }

    // 3. 不安全的Velocity模板处理
    @GetMapping("/template/bad03")
    public String processVelocityTemplate(@RequestParam String userInput) {
        try {
            VelocityEngine velocityEngine = new VelocityEngine();
            Properties props = new Properties();
            props.put("runtime.log.logsystem.class", "org.apache.velocity.runtime.log.NullLogSystem");
            velocityEngine.init(props);

            VelocityContext context = new VelocityContext();
            context.put("user", "admin");

            StringWriter writer = new StringWriter();
            // 直接使用用户输入作为模板
            velocityEngine.evaluate(context, writer, "userTemplate", userInput);

            return writer.toString();
        } catch (Exception e) {
            return "Velocity template processing error: " + e.getMessage();
        }
    }

    // 4. 不安全的动态模板路径
    @GetMapping("/template/bad04")
    public String processTemplateFromPath(@RequestParam String templatePath) {
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
            // 不安全：允许用户控制模板路径
            cfg.setDirectoryForTemplateLoading(new File(templatePath));
            Template template = cfg.getTemplate("template.ftl");

            Map<String, Object> dataModel = new HashMap<>();
            dataModel.put("user", "admin");

            StringWriter writer = new StringWriter();
            template.process(dataModel, writer);

            return writer.toString();
        } catch (Exception e) {
            return "Template processing error: " + e.getMessage();
        }
    }

    // 5. 不安全的模板字符串拼接
    @GetMapping("/template/bad05")
    public String processTemplateWithConcat(@RequestParam String userName) {
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
            // 不安全：在模板中拼接用户输入
            String templateContent = "Hello ${" + userName + "}!";
            Template template = new Template("userTemplate",
                    new StringReader(templateContent),
                    cfg);

            Map<String, Object> dataModel = new HashMap<>();
            StringWriter writer = new StringWriter();
            template.process(dataModel, writer);

            return writer.toString();
        } catch (Exception e) {
            return "Template processing error: " + e.getMessage();
        }
    }

    // 6. 不安全的模板引擎配置 - 修正版本
    @GetMapping("/template/bad06")
    public String processTemplateWithUnsafeConfig(@RequestParam String userInput) {
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);

            // 设置模板解析器 - 这里展示三种可能的配置方式
            // 1. 允许所有类（不安全）
            cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);

            // 2. 仅允许指定包下的类（较安全）
            // cfg.setNewBuiltinClassResolver(new TemplateClassResolver(
            //     TemplateClassResolver.SAFER_RESOLVER,
            //     "com.yourcompany.allowed.package."
            // ));

            // 3. 禁止所有类（最安全）
            // cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);

            Template template = new Template("userTemplate",
                    new StringReader(userInput),
                    cfg);

            Map<String, Object> dataModel = new HashMap<>();
            StringWriter writer = new StringWriter();
            template.process(dataModel, writer);

            return writer.toString();
        } catch (Exception e) {
            return "Template processing error: " + e.getMessage();
        }
    }

    // 7. 安全的模板处理示例
    @GetMapping("/template/good01")
    public String processSecureTemplate(@RequestParam String userInput) {
        try {
            Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);

            // 使用安全的配置
            cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);

            // 设置模板加载目录
            cfg.setClassForTemplateLoading(this.getClass(), "/templates");

            // 使用预定义的模板而不是用户输入
            Template template = cfg.getTemplate("secure_template.ftl");

            // 安全处理用户输入：将其作为数据模型的一部分
            Map<String, Object> dataModel = new HashMap<>();
            dataModel.put("sanitizedUserInput", escapeUserInput(userInput));

            StringWriter writer = new StringWriter();
            template.process(dataModel, writer);

            return writer.toString();
        } catch (Exception e) {
            return "Template processing error: " + e.getMessage();
        }
    }

    // 辅助方法：转义用户输入
    private String escapeUserInput(String input) {
        if (input == null) {
            return "";
        }
        // 实现基本的HTML转义
        return input.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;")
                .replace("&", "&amp;");
    }
}