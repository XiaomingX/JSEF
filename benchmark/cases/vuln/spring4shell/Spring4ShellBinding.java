// [VULN]
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — Spring4Shell CVE-2022-22965 (A01 越权/数据绑定，难度 L4)
 *
 * 危险入口：Spring MVC 直接将请求参数绑定到 POJO（无字段白/黑名单限制），
 * 攻击者可利用 class.module.classLoader... 链修改 Tomcat 日志相关属性，
 * 结合文件写入实现 RCE。此处仅演示危险绑定链，不写真实利用脚本。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实 RCE 利用脚本。
 */
@RestController
public class Spring4ShellBinding {

    public static class Account {
        private String name;
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    /**
     * 危险：@ModelAttribute 无限制绑定，暴露 class.module.* 危险属性链。
     * 攻击者请求 ?class.module.classLoader.resources.context.parent.pipeline...
     * 可改写 Tomcat 日志路径/后缀（RCE 前置步骤）。
     */
    @PostMapping("/account/update")
    public String update(@ModelAttribute Account account) { // 未限定可写字段
        // [CHECKPOINT id=JSEF-S4S-001 cwe=94 level=L4 source=class.module.classLoader request params sink=POJO data binding (class.module.*) expect=VULN]
        return "updated " + account.getName();
    }
}
