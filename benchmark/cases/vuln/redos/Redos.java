// [VULN]
package com.jsef.benchmark.vuln;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * JSEF-Benchmark — ReDoS 正则拒绝服务 (CWE-1333，难度 L2)
 *
 * 危险入口：攻击者提供的正则（或攻击者输入 + 灾难性回溯正则）被直接用于匹配。
 * 灾难性回溯正则如 (a+)+$ 在匹配失败输入上呈指数级回溯，导致 CPU 长时间占满。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供用于真实 DoS 的长输入。
 */
public class Redos {

    /**
     * 危险：用不可信正则编译并匹配不可信输入，可导致 ReDoS。
     */
    static boolean match(String userProvidedRegex, String userInput) {
        // [CHECKPOINT id=JSEF-REDOS-001 cwe=1333 level=L2 source=userProvidedRegex sink=Pattern.compile expect=VULN]
        Pattern p = Pattern.compile(userProvidedRegex); // 灾难性回溯正则 (a+)+$ 由攻击者控制
        Matcher m = p.matcher(userInput);
        return m.matches();
    }

    /**
     * 危险：硬编码的灾难性回溯正则匹配不可信输入。
     */
    static boolean matchEvil(String userInput) {
        // [CHECKPOINT id=JSEF-REDOS-002 cwe=1333 level=L2 source=userInput sink=Pattern.matcher expect=VULN]
        Pattern p = Pattern.compile("(a+)+$"); // 灾难性回溯
        return p.matcher(userInput).matches();
    }
}
