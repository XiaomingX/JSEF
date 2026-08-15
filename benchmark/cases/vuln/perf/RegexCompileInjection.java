package com.jsef.benchmark.vuln.perf;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * JSEF-Benchmark A2「代码质量/性能 DoS」— ReDoS：外部可控正则编译（L2 注入版）
 *
 * 子目标清单：
 *   ① 识别把不可信用户输入直接作为正则 pattern 传给 Pattern.compile()；
 *   ② 识别恶意构造的正则（如 (a+)+$、嵌套量词）可在特定输入上触发指数级回溯；
 *   ③ 区分「用户输入作为 pattern（危险）」与「用户输入作为匹配内容（安全）」；
 *   ④ 识别修复方向：仅使用白名单/锚定的固定正则，用户输入只作为待匹配文本。
 *
 * 可达性说明：
 *   source = 外部请求中的 regex 参数（类比请求参数），直接作为
 *   Pattern.compile(userInput) 的 pattern 参数，L2（参数传入 + 编译两步语义）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供恶意回溯正则生成器/DoS 利用脚本，不针对真实服务。
 *
 * 修复要点（对照 RegexCompileInjection_Safe.java）：
 *   正则 pattern 固定为白名单/锚定常量；不可信输入仅作为 matcher 的匹配内容。
 *
 * CWE-1333（ReDoS / 不受控正则复杂度）。
 */
public class RegexCompileInjection {

    /**
     * 把不可信 regex 直接编译：攻击者可用嵌套量词构造指数回溯 DoS。
     */
    public boolean compileAndMatch(String userRegex, String input) {
        // [CHECKPOINT id=JSEF-PERF-REDOS-001 cwe=1333 level=L2 source=requestParam(userRegex) sink=Pattern.compile expect=VULN]
        // 缺陷：外部可控正则被直接编译，恶意 pattern 在特定输入上触发灾难性回溯 → CPU DoS
        Pattern p = Pattern.compile(userRegex);
        return p.matcher(input).matches();
    }

    public static void main(String[] args) {
        try {
            boolean ok = new RegexCompileInjection().compileAndMatch("(a+)+$", "aaaa");
            System.out.println(ok);
        } catch (PatternSyntaxException e) {
            System.out.println("bad regex");
        }
    }
}
