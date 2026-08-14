// [VULN]
// 漏洞样本：ReDoS——用户自定义正则 + 超长输入
// 漏洞点：允许用户输入任意正则表达式并匹配超长字符串，可触发灾难性回溯。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：使用用户提供的正则匹配用户输入。
 */
@RestController
@RequestMapping("/benchmark/vuln/regex-dos")
public class RegexDosVulnB {

    /**
     * 不安全示例：用户提供的正则无长度限制。
     */
    @GetMapping("/unsafe/user-provided-pattern")
    public boolean unsafeRegexWithUserPattern(
            @RequestParam String userProvidedRegex,
            @RequestParam String inputString) {
        // 危险实践：用户正则 + 用户超长输入，存在 ReDoS
        // [CHECKPOINT id=JSEF-REGEXDOS-002 cwe=1333 level=L1 source=@RequestParam userProvidedRegex,inputString sink=String.matches(userProvidedRegex) expect=VULN]
        return inputString.matches(userProvidedRegex);
    }
}
