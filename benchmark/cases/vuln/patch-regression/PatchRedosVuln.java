// [VULN]
package com.jsef.benchmark.vuln.patchregression;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 1
 * 主题：输入校验补丁引入 ReDoS / 拒绝服务 (CWE-1333，难度 L4)
 *
 * 反模式：原始实现对用户提交的内容直接做 String.matches(regex)，正则由攻击者控制，
 * 形成经典 ReDoS（灾难性回溯）。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   原代码用不可信/危险正则在用户输入上执行匹配，攻击者构造灾难性回溯正则
 *   或匹配失败长输入即可让 CPU 长时间占满 —— 拒绝服务。
 *   修复方案（见 sec）：服务端应固定一份"安全白名单正则"，并对输入长度、正则编译
 *   做限制；绝不允许把用户输入当作正则本身。
 *
 * 安全底线：仅 localhost 演示语义，不写真实 DoS 利用，不生成针对真实目标的工具。
 */
public class PatchRedosVuln {

    /**
     * 危险：用攻击者提供的正则去匹配另一份用户输入。
     * 攻击者只需提交灾难性回溯正则（如 (a+)+$）即可触发 ReDoS。
     */
    static boolean validateByUserRegex(String userProvidedRegex, String userInput) {
        // [CHECKPOINT id=JSEF-PR-001 cwe=1333 level=L4 source=userProvidedRegex sink=String.matches expect=VULN]
        return userInput.matches(userProvidedRegex); // String.matches 内部 Pattern.compile 用户正则
    }
}
