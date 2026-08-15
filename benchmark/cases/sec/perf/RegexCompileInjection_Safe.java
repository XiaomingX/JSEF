package com.jsef.benchmark.sec.perf;

import java.util.regex.Pattern;

/**
 * JSEF-Benchmark A2「代码质量/性能 DoS」— ReDoS 安全对照（L2 注入版）
 *
 * 子目标清单（对照 RegexCompileInjection.java）：
 *   ① 识别正则 pattern 为固定白名单/锚定常量，拒绝外部可控；
 *   ② 确认不可信输入仅作为 matcher 的匹配内容，而非 pattern；
 *   ③ 区分「固定 pattern + 外部内容」与「外部 pattern + 任意内容」；
 *   ④ 验证修复后即使输入量词嵌套，pattern 复杂度仍由开发者可控。
 *
 * 可达性说明：
 *   source = 外部请求中的 input（仅作为匹配内容），pattern 为固定常量，
 *   L2（固定 pattern + 外部内容两步语义）。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供恶意回溯正则生成器/DoS 利用脚本，不针对真实服务。
 *
 * 修复要点：
 *   正则 pattern 固定为锚定常量；不可信输入仅作为 matcher 匹配内容。
 *
 * CWE-1333（已规避）。
 */
public class RegexCompileInjection_Safe {

    // 固定、锚定的白名单正则：仅允许简单字母数字标识，无嵌套量词
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[A-Za-z0-9_]+$");

    /**
     * 使用固定 pattern，不可信输入只作为匹配内容，避免恶意回溯 DoS。
     */
    public boolean safeMatch(String input) {
        // [CHECKPOINT id=JSEF-PERF-REDOS-001S cwe=1333 level=L2 source=requestParam(input) sink=Pattern.compile expect=SAFE]
        // 修复：pattern 为固定白名单常量，不可信输入仅作为 matcher 内容，复杂度可控，无 ReDoS
        return SAFE_PATTERN.matcher(input).matches();
    }

    public static void main(String[] args) {
        System.out.println(new RegexCompileInjection_Safe().safeMatch("user_123"));
    }
}
