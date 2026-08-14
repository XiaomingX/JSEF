// [SAFE]
// 安全对照：正则表达式 DOS / ReDoS（修复版）
// 修复原则：限制输入长度、使用简单正则、设置匹配超时，避免灾难性回溯。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 安全示例：限制输入长度并使用简单正则，避免 ReDoS。
 */
@RestController
@RequestMapping("/benchmark/sec/regex-dos")
public class RegexDosSafe {

    /**
     * 安全示例：限定长度 + 简单正则（无嵌套重复）。
     */
    @GetMapping("/safe/nested-repetition")
    public boolean safeRegexWithNestedRepetition(@RequestParam String inputString) {
        // 防护1：限制输入长度
        if (inputString == null || inputString.length() > 100) {
            return false;
        }
        try {
            // 防护2：使用简单正则，无 (a+)+b 式嵌套重复
            // [CHECKPOINT id=JSEF-REGEXDOS-001S cwe=1333 level=L1 source=@RequestParam inputString sink=Pattern.matches (simple regex + length limit, no ReDoS) expect=SAFE]
            Pattern pattern = Pattern.compile("[a-zA-Z0-9]+", Pattern.CASE_INSENSITIVE);
            return pattern.matcher(inputString).matches();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
}
