package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 org.springframework 框架类（@ModelAttribute、DataBinder 语义），
 * 用于静态分析 / LLM 阅读，不强求 mvn 编译通过，但语义正确、可读。
 *
 * JSEF-Benchmark L4 — 框架语义依赖（批量赋值 / mass-assignment）
 *
 * 难度：L4（框架语义）。纯语法工具难以识别：@ModelAttribute 把整张 HTTP 表单
 * 自动绑定到领域对象的所有可写属性，攻击者借此写入危险字段（如 role/isAdmin），
 * 该字段随后直接进入权限判断 / sink。污点不是显式赋值，而是框架在绑定阶段隐式写入。
 *
 * CWE-915 (Mass Assignment) / 业务权限提升。
 *
 * 安全底线：仅展示绑定语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */

import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * JSEF-Benchmark L4 — @ModelAttribute 绑定到危险字段后入 sink。
 */
public class SpringBindingTaint {

    // 绑定目标：框架会把表单所有字段写入可写属性，包括危险字段 role
    public static class AccountForm {
        private String username;
        private String role; // 危险字段：框架语义允许攻击者通过表单写入
        public String getUsername() { return username; }
        public void setUsername(String v) { this.username = v; }
        public String getRole() { return role; }
        public void setRole(String v) { this.role = v; }
    }

    /**
     * 危险入口：@ModelAttribute 隐式把 role 字段绑定为不可信值，
     * 随后 role 直接用于权限判断（sink，授权语义）。
     *
     * @param form 框架自动绑定后的表单对象
     */
    public String handle(@ModelAttribute AccountForm form) {
        // 框架语义：form.role 已被攻击者表单值污染
        // [CHECKPOINT id=JSEF-L4-BIND-001 cwe=915 level=L4 source=@ModelAttribute(form.role) sink=authorization check on role expect=VULN]
        if ("ADMIN".equals(form.getRole())) {
            return "granted-admin"; // 不可信 role 驱动越权授权
        }
        return "user";
    }

    public static void main(String[] args) {
        AccountForm f = new AccountForm();
        f.setRole("ADMIN"); // 模拟攻击者批量赋值
        System.out.println(new SpringBindingTaint().handle(f));
    }
}
