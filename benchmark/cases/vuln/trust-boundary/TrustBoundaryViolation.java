/*
 * JSEF Benchmark 样本 — 信任边界违反：不可信请求参数跨信任边界直写 HttpSession（B1 组，CWE-501，L3）
 *
 * ① 子目标清单：
 *    - 演示"信任边界"概念：HTTP 请求参数属不可信域（L1 客户端），HttpSession 属服务端可信域。
 *    - 展示 source（@RequestParam）→ sink（HttpSession.setAttribute）跨越信任边界写入。
 *    - 让静态分析识别"未校验的不可信输入被直接写入可信会话存储"。
 * ② 可达性说明：
 *    - source：Controller 方法形参 userKey / userVal（来自 HTTP 请求）。
 *    - sink：request.getSession().setAttribute(name, value) 将未校验值写入 session。
 *    - data flow：userKey、userVal 不经任何白名单/校验，直接进 setAttribute，跨越信任边界。
 * ③ 安全底线：仅 localhost 演示语义，不写真实利用脚本，不提供跨站点污染攻击 payload。
 * ④ 修复要点：见 sec 文件 TrustBoundaryViolation_Safe.java —— 仅允许服务端预设的 key，
 *    且对 value 做类型/格式校验后才写入 session；不可信输入不得作为 session key。
 */
package com.jsef.benchmark.vuln.trustboundary;

import jakarta.servlet.http.HttpServletRequest;

public class TrustBoundaryViolation {

    // source：不可信 HTTP 请求参数直接作为方法输入
    public void storeUntrusted(HttpServletRequest request, String userKey, String userVal) {
        // [CHECKPOINT id=JSEF-TB-001 cwe=501 level=L3 source=HttpServletRequest parameter sink=HttpSession.setAttribute(name, taintedValue) expect=VULN trace=benchmark/cases/vuln/trust-boundary/TrustBoundaryViolation.java:23,benchmark/cases/vuln/trust-boundary/TrustBoundaryViolation.java:26]
        // 危险：userKey / userVal 未经任何校验即跨越信任边界写入可信 session
        request.getSession().setAttribute(userKey, userVal);
    }
}
