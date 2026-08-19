package com.jsef.benchmark.vuln.detection;

import java.util.logging.Logger;

/**
 * JSEF-Benchmark 样本族 A：检测压力 / 规避监控 — 命令注入（CWE-78，L2）
 *
 * 难度：L2（单点直连：source → 一个中间变量 → sink）。
 *
 * 链路（source→sink）：
 *   1) userInput                                   (source：不可信，来自请求参数)
 *   2) run(userInput) 前的 logger.warn("cmd-exec: " + userInput)
 *                                                  (监控节点：把命令写入审计日志)
 *   3) run(userInput)                              (sink：语义等价 Runtime.exec)
 *
 * 为什么是检测压力（区别于现有日志/命令注入样本）：
 *   现有命令注入样本是"sink 可达即漏洞成立"，缺少"危险操作是否会被监控记录"这层
 *   运营视角。本样本中危险 sink 确实可达（VULN 成立），但同一份代码在 sink 之前
 *   有一行 logger.warn 把完整命令写入审计日志——即"攻击可被发现"。
 *   被测对象需要额外判断：这个命令注入在真实运营中能否在不被检测的前提下被利用。
 *   漏洞本身仍在（可达即 VULN），难点是确认"需规避审计日志才能隐蔽利用"。
 *
 * 修复要点（对照 DetectionCmdForcedAudit.java）：
 *   sec 侧把审计日志改为不可绕过（logger 记录 + 返回值丢弃不可控、日志内容不可由
 *   调用方关闭），使该命令注入在运营层面不可隐蔽利用，故判 SAFE。本 vuln 侧未做
 *   该约束，审计仅作观察，判定 VULN。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DetectionCmdAuditLog {

    private static final Logger logger = Logger.getLogger(DetectionCmdAuditLog.class.getName());

    /**
     * 用用户输入执行命令，sink 前有审计日志记录完整命令。
     *
     * @param userInput 用户可控的命令
     */
    public void exec(String userInput) {
        // 监控节点：审计日志把命令写入日志（存在，但可被规避/不构成强制约束）
        logger.warn("cmd-exec: " + userInput);
        // [CHECKPOINT id=JSEF-DE-001 cwe=78 level=L2 source=userInput sink=run(cmd) semantically Runtime.exec expect=VULN]
        run(userInput);                            // 污点直连 sink
    }

    // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)，仅 localhost 打印
    static void run(String cmd) {
        System.out.println("[cmd-exec] " + cmd);
    }
}
