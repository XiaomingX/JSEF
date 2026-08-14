// [SAFE]
package com.jsef.benchmark.sec;

import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — Spring4Shell 安全对照 (CVE-2022-22965，难度 L4)
 *
 * 修复：使用 @InitBinder 的 setDisallowedFields 禁用 class.* / module.* 等
 * 危险属性，或通过 DTO 仅接受预期字段，阻断 class.module.classLoader 绑定链。
 */
@RestController
public class Spring4ShellBindingSafe {

    public static class AccountDto {
        private String name;
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // [CHECKPOINT id=JSEF-S4S-001S cwe=94 level=L4 source=class.module.classLoader request params sink=setDisallowedFields expect=SAFE]
        binder.setDisallowedFields("class.*", "module.*", "*.class.*", "*.module.*");
    }

    @PostMapping("/account/update")
    public String update(@ModelAttribute AccountDto account) {
        return "updated " + account.getName();
    }
}
