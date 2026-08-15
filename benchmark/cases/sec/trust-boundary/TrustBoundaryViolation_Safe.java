/*
 * JSEF Benchmark 样本 — 信任边界违反（安全对照）：白名单校验后才写入 session（B1 组，CWE-501，L3）
 *
 * ① 子目标清单：
 *    - 演示如何修正信任边界违反：不可信 key 不得直接进入 session。
 *    - key 必须为服务端预设白名单；value 做格式/类型校验。
 * ② 可达性说明：
 *    - userKey 经 ALLOWED_KEYS 白名单校验后才被接受；userVal 仅作值，且经空/长度校验。
 *    - 写入 session 的 key 是受控常量，不可信输入不构成信任边界跨越。
 * ③ 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 * ④ 修复要点：白名单校验 key + value 校验，杜绝不可信输入直接成为 session 键/值。
 */
package com.jsef.benchmark.sec.trustboundary;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;

public class TrustBoundaryViolation_Safe {

    // 服务端预设的可信 key 白名单
    private static final Set<String> ALLOWED_KEYS = Set.of("theme", "locale", "pageSize");

    public void storeTrusted(HttpServletRequest request, String userKey, String userVal) {
        // 修复：仅白名单内的 key 才被接受；value 做基本校验
        if (!ALLOWED_KEYS.contains(userKey)) {
            return; // 不可信 key 直接拒绝，不跨越信任边界
        }
        if (userVal == null || userVal.length() > 64) {
            return; // value 校验
        }
        // [CHECKPOINT id=JSEF-TB-001S cwe=501 level=L3 source=HttpServletRequest parameter sink=HttpSession.setAttribute(name, validatedValue) expect=SAFE trace=benchmark/cases/sec/trust-boundary/TrustBoundaryViolation_Safe.java:25,benchmark/cases/sec/trust-boundary/TrustBoundaryViolation_Safe.java:32]
        request.getSession().setAttribute(userKey, userVal);
    }
}
