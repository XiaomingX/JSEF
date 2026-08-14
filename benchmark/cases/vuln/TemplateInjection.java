/*
 * JSEF Benchmark 样本 — 模板注入（D7，CWE-1336，L3）
 * 运行态需 JSEF 依赖（FreeMarker / Thymeleaf 等模板引擎）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实 RCE 利用模板。
 *
 * 知识点（CAP-09，L3 框架语义）：
 *   模板引擎（FreeMarker/Thymeleaf 风格）会把"模板内容/模板名"当作可执行的模板语言求值。
 *   若用户可控的模板名或模板内容被直接交给 TemplateEngine.process()，
 *   攻击者可注入模板表达式（如 FreeMarker 的 <#assign ex="freemarker.template.utility.Execute"?new()>），
 *   从而被引擎求值 → 信息泄露甚至 RCE。
 *   sink 是 TemplateEngine.process，source 是用户可控的模板名/内容（框架语义级危险）。
 */
import java.util.Map;

public class TemplateInjection {

    // 演示用引擎接口（语义同 FreeMarker/Thymeleaf TemplateEngine）
    interface TemplateEngine { String process(String templateName, Map<String, Object> model); }

    /**
     * 危险入口：用户可控的模板名/内容直接送入引擎求值。
     */
    static String render(TemplateEngine engine, String userTemplate, Map<String, Object> model) {
        // source：不可信模板名/内容（HTTP 请求传入，攻击者可控）
        // [CHECKPOINT id=JSEF-TEMPLATE-001 cwe=1336 level=L3 source=user-controlled template name/content sink=TemplateEngine.process expect=VULN]
        return engine.process(userTemplate, model);   // 模板被求值 → 注入可达
    }
}
