// [VULN]
package com.jsef.benchmark.sec;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark — 子目标 B2-3 安全对照：forward 路径 allowlist 校验 (CWE-98，SAFE)
 *
 * ① 子目标清单：
 *    - 定义允许的转发目标白名单；
 *    - 仅当用户路径命中白名单时才转发，否则返回 400。
 *
 * ② 可达性说明：
 *    转发目标受 ALLOWED 白名单约束，不可信 path 参数无法驱动到非白名单视图，
 *    sink 仅接收受信路径 → 不可达越权转发。
 *
 * ③ 安全底线（仅 localhost 演示，无真实利用脚本）：
 *    仅演示安全写法，不提供任何攻击脚本。
 *
 * ④ 修复要点：
 *    白名单匹配后再 getRequestDispatcher，拒绝未命中。
 */
public class UnvalidatedForward_Safe {

    private static final List<String> ALLOWED = Arrays.asList("/home", "/profile", "/dashboard");

    /**
     * 安全：仅当路径命中白名单时才 forward。
     */
    static void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String userPath = req.getParameter("path");
        if (!ALLOWED.contains(userPath)) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid forward target");
            return;
        }
        RequestDispatcher dispatcher = req.getRequestDispatcher(userPath);
        // [CHECKPOINT id=JSEF-FWD-001S cwe=98 level=L2 source=request.getParameter(path) sink=RequestDispatcher.forward expect=SAFE]
        dispatcher.forward(req, resp);
    }
}
