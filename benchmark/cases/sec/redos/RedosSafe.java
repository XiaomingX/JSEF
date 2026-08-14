// [SAFE]
package com.jsef.benchmark.sec;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * JSEF-Benchmark — ReDoS 安全对照 (CWE-1333，难度 L2)
 *
 * 修复：使用预编译的白名单安全正则（线性时间、无嵌套量词），并限制输入长度，
 * 避免灾难性回溯。
 */
public class RedosSafe {

    // 预编译的安全正则：原子、无嵌套量词，线性时间
    private static final Pattern SAFE_PATTERN = Pattern.compile("[a-z]+");

    /**
     * 安全：使用预编译白名单正则，拒绝不可信正则来源。
     */
    static boolean match(String userInput) {
        if (userInput.length() > 1000) {
            return false; // 限制输入长度，进一步降低 DoS 风险
        }
        // [CHECKPOINT id=JSEF-REDOS-001S cwe=1333 level=L2 source=userInput sink=SAFE_PATTERN.matcher expect=SAFE]
        Matcher m = SAFE_PATTERN.matcher(userInput);
        return m.matches();
    }
}
