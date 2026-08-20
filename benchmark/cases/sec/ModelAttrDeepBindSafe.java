package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * JSEF-Benchmark L4 — @ModelAttribute 深度绑定安全对照（SAFE）
 *
 * 安全做法：即使攻击者通过 form.prefs.role 深度绑定写入任意 role，
 * 服务端在授权决策前会忽略表单中的 role 字段并**强制覆写**为白名单角色，
 * 或直接从可信会话取角色。被污染的 role 不再驱动授权。
 *
 * CWE-915 (Mass Assignment)。
 */
public class ModelAttrDeepBindSafe {

    public static class UserPrefs {
        private String role; // 即使被表单写入，也会被服务端覆写
        public String getRole() { return role; }
        public void setRole(String v) { this.role = v; }
    }

    public static class AccountForm {
        private String username;
        private UserPrefs prefs = new UserPrefs();
        public String getUsername() { return username; }
        public void setUsername(String v) { this.username = v; }
        public UserPrefs getPrefs() { return prefs; }
        public void setPrefs(UserPrefs v) { this.prefs = v; }
    }

    /**
     * 安全入口：绑定后服务端强制覆写 role 为白名单值，忽略不可信表单字段。
     *
     * @param form 深度绑定后的表单（含攻击者写入的 form.prefs.role）
     */
    public String handleSafe(@ModelAttribute AccountForm form) {
        // 服务端覆写：role 一律以白名单为准，丢弃表单中的污染值
        String role = resolveRoleFromTrustedSource(form.getUsername());
        // [CHECKPOINT id=JSEF-MAB-001S cwe=915 level=L4 source=@ModelAttribute(form.prefs.role) sink=authorization check on role expect=SAFE]
        if ("ADMIN".equals(role)) { // role 来自可信来源，非表单污染值
            return "granted-admin";
        }
        return "user";
    }

    // 可信角色解析：仅允许服务端判定，绝不采用表单传入的 role
    private String resolveRoleFromTrustedSource(String username) {
        return "USER"; // 固定白名单角色；真实系统中从可信会话/DB 取值
    }

    public static void main(String[] args) {
        AccountForm f = new AccountForm();
        f.getPrefs().setRole("ADMIN"); // 攻击者写入，但会被服务端覆写
        System.out.println(new ModelAttrDeepBindSafe().handleSafe(f));
    }
}
