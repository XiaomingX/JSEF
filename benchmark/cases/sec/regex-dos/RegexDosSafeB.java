// [SAFE]
// 安全对照：ReDoS——用户自定义正则（修复版）
// 修复原则：限制输入长度、禁用危险构造；使用简单白名单正则替代用户输入。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;
import java.util.regex.Pattern;

/**
 * 安全示例：不使用用户提供的正则，限制长度并使用简单模式。
 */
@RestController
@RequestMapping("/benchmark/sec/regex-dos")
public class RegexDosSafeB {

    /**
     * 安全示例：忽略用户正则，使用受信任简单模式 + 长度限制。
     */
    @GetMapping("/safe/user-provided-pattern")
    public boolean safeRegexWithUserPattern(
            @RequestParam String userProvidedRegex,
            @RequestParam String inputString) {
        if (inputString == null || inputString.length() > 100) {
            return false;
        }
        // 安全实践：不使用用户提供的正则，避免 ReDoS
        // [CHECKPOINT id=JSEF-REGEXDOS-002S cwe=1333 level=L1 source=@RequestParam userProvidedRegex,inputString sink=Pattern.matches (trusted simple regex, no user pattern) expect=SAFE]
        Pattern pattern = Pattern.compile("[A-Za-z0-9 ]+");
        return pattern.matcher(inputString).matches();
    }
}
