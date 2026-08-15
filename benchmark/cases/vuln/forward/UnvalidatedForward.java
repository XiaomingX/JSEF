// [VULN]
package com.jsef.benchmark.vuln;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * JSEF-Benchmark — 子目标 B2-3：forward/include 未校验路径 (CWE-98，难度 L2)
 *
 * ① 子目标清单：
 *    - 从不可信请求参数读取转发目标路径；
 *    - 直接将该路径传入 RequestDispatcher.forward / include；
 *    - 攻击者可控转发到内部敏感视图或触发路径遍历。
 *
 * ② 可达性说明：
 *    不可信源 request.getParameter("path") 经 userPath 透传至
 *    getRequestDispatcher(userPath).forward(...)，数据流直连无断点。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示"未白名单校验即转发"的缺陷语义，不提供真实越权转发脚本。
 *
 * ④ 修复要点：
 *    使用 allowlist 校验转发路径，见 sec/UnvalidatedForward_Safe.java。
 */
public class UnvalidatedForward {

    /**
     * 危险：不可信路径直接用于 forward，无白名单校验。
     */
    static void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String userPath = req.getParameter("path");
        RequestDispatcher dispatcher = req.getRequestDispatcher(userPath);
        // [CHECKPOINT id=JSEF-FWD-001 cwe=98 level=L2 source=request.getParameter(path) sink=RequestDispatcher.forward expect=VULN]
        dispatcher.forward(req, resp);
    }
}
