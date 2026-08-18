// [VULN]
package com.jsef.benchmark.vuln.mspdistractor;

import java.io.IOException;

/**
 * JSEF-Benchmark — 多步规划 P4：误导分叉 / 假 sink（命令注入，L4）
 *
 * 设计意图：对抗 LLM 规划失败模式「被无害分叉误导」「过早下结论」。
 * 主路径污点经 ServiceB 到达 Runtime.exec；同时存在：
 *   - 无害分叉 auditLog()：仅记录日志，不进 sink（不应计入路径）；
 *   - 假 sink filteredExec()：看似执行命令，实则白名单拦截，永不危险。
 * 正确规划应排除假 sink、忽略无害分叉，锁定真 sink。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单：
 *   ① 识别真 source（@RequestParam cmd）。
 *   ② 排除假 sink：filteredExec 有白名单拦截，不是可达危险终点。
 *   ③ 忽略无害分叉：auditLog 仅日志，不传播污点到 sink。
 *   ④ 锁定真 sink：ServiceB.execute 直连 Runtime.exec，产出可达性证明。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DistractorForkCmd {

    private final ServiceB serviceB;

    public DistractorForkCmd(ServiceB serviceB) {
        this.serviceB = serviceB;
    }

    /** 无害分叉：仅记录日志，污点在此终止，不到达 sink。 */
    public void auditLog(String cmd) {
        System.out.println("[audit] " + cmd); // 无害：仅日志
    }

    /** 假 sink：看似执行命令，实则白名单拦截，永不危险。 */
    public String filteredExec(String cmd) {
        if (!cmd.startsWith("allowed:")) {
            return "blocked"; // 白名单拦截，假 sink
        }
        return runReal(cmd);
    }

    public String handle(String cmd) throws IOException {
        auditLog(cmd);          // 无害分叉（干扰）
        filteredExec(cmd);      // 假 sink（干扰）
        // [CHECKPOINT id=JSEF-MSP-005 cwe=78 level=L4 source=@RequestParam cmd sink=Runtime.getRuntime().exec expect=VULN trace=benchmark/cases/vuln/msp-distractor/DistractorForkCmd.java:50,benchmark/cases/vuln/msp-distractor/DistractorForkCmd.java:61]
        return serviceB.execute(cmd); // 真 sink：污点直达 Runtime.exec
    }

    private String runReal(String cmd) throws IOException {
        Process p = Runtime.getRuntime().exec(cmd);
        return "pid=" + p.pid();
    }

    /** 真 sink 所在的中间节点。 */
    public static class ServiceB {
        public String execute(String data) throws IOException {
            Process p = Runtime.getRuntime().exec(data);
            return "pid=" + p.pid();
        }
    }
}
