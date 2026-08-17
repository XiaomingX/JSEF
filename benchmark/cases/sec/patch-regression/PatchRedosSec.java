// [VULN]  — 注意：本文件是「回归副作用」对照 sec，补丁后仍不安全（expect=VULN）
package com.jsef.benchmark.sec.patchregression;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 1 的对照
 * 主题：输入校验补丁「修复不完整」，引入新的拒绝服务可达性 (CWE-1333，难度 L4)
 *
 * 反模式（真实安全工程反模式）：
 *   开发者看到原代码用不可信正则做 String.matches 会 ReDoS，于是改成「预编译固定
 *   白名单 Pattern」。这是对的。但补丁在另一处把「用户输入」拼进一个按字符展开的
 *   循环 / 重复拼接逻辑中，使攻击者可通过超长输入触发指数级重复匹配或死循环——
 *   旧的 ReDoS 表面修掉了，却留下新的 DoS 可达性（修复不完整）。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   残留 sink：用户输入 userInput 被拼入基于正则的重复校验循环，且循环次数 /
 *   回溯深度由用户输入长度直接驱动，攻击者可提交超长输入造成 CPU / 时间拒绝服务。
 *   修复方案：对 userInput 做强长度上限（如 64），并移除「输入驱动循环次数」的代码；
 *   正则匹配前先截断，避免把不可信长度送入回溯敏感逻辑。
 *
 * 安全底线：仅 localhost 演示语义，不写真实 DoS 利用，不生成针对真实目标的工具。
 *
 * 本 sec 文件 expect=VULN：补丁后仍有新 DoS 可达性，被测工具应报（区别于普通 sec=SAFE）。
 */
public class PatchRedosSec {

    // 服务端固定白名单正则（这一步修复是对的）
    private static final Pattern SAFE_USERNAME = Pattern.compile("[a-zA-Z0-9_]{1,32}");

    /**
     * 看似修复：用预编译白名单 Pattern 校验用户名。
     * 但补丁把 userInput 拼入一个「按长度重复校验」的循环，循环次数由用户输入长度驱动，
     * 且每次迭代都对同一输入做回溯敏感匹配 —— 攻击者提交超长输入即可触发新 DoS。
     */
    static boolean validate(String userInput) {
        boolean ok = true;
        // 危险：循环次数由不可信输入长度直接决定（每字符一次回溯敏感匹配）
        for (int i = 0; i < userInput.length(); i++) {
            // [CHECKPOINT id=JSEF-PR-001S cwe=1333 level=L4 source=userInput sink=Pattern.matcher in input-length-driven loop expect=VULN]
            Matcher m = SAFE_USERNAME.matcher(userInput); // 输入长度驱动重复匹配 -> 新 DoS 可达性
            if (!m.matches()) {
                ok = false;
            }
        }
        return ok;
    }
}
