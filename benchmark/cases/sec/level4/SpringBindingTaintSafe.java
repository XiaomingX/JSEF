package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — SpringBindingTaint 安全对照（SAFE 混淆样本）
 *
 * 安全做法：使用 DTO 仅暴露安全字段，忽略危险字段（如 role）；
 * 或使用 @InitBinder setDisallowedFields 禁止绑定 role。用于计算 TN / FP。
 *
 * CWE-915 Mass Assignment。
 */
import org.springframework.web.bind.annotation.ModelAttribute;

public class SpringBindingTaintSafe {

    // DTO：仅暴露安全字段，role 不在绑定范围内
    public static class AccountDto {
        private String username;
        public String getUsername() { return username; }
        public void setUsername(String v) { this.username = v; }
    }

    public String handle(@ModelAttribute AccountDto form) {
        // role 不可由表单写入，授权来源于服务端会话，非不可信输入
        // [CHECKPOINT id=JSEF-L4-BIND-001S cwe=915 level=L4 source=@ModelAttribute(form) sink=authorization check on role expect=SAFE]
        String role = roleFromSession(); // 服务端受控，非不可信绑定
        if ("ADMIN".equals(role)) {
            return "granted-admin";
        }
        return "user";
    }

    private String roleFromSession() {
        return "USER"; // 受信任来源
    }

    public static void main(String[] args) {
        AccountDto f = new AccountDto();
        f.setUsername("localhost-demo");
        System.out.println(new SpringBindingTaintSafe().handle(f));
    }
}
