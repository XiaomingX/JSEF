package com.jsef.benchmark.sec.detection;

import java.util.logging.Logger;

/**
 * JSEF-Benchmark 样本族 A：检测压力 — 命令注入 SAFE 对照：强制不可绕过审计（CWE-78，L2）
 *
 * 难度：L2（单点直连：source → 强制审计 → 安全 sink）。
 *
 * 链路（source→sink）：
 *   1) userInput                                   (source：不可信，来自请求参数)
 *   2) forcedAudit(userInput)                      (安全节点：强制审计，返回状态被丢弃不可控)
 *   3) runGuarded(userInput)                       (安全 sink：被审计保护的命令执行)
 *
 * 为什么是 SAFE（区别于 DetectionCmdAuditLog.java 的 VULN 侧）：
 *   同是命令注入场景（sink 语义等价 Runtime.exec），但本样本在 sink 前有强制审计：
 *   审计调用将命令 + 调用方写入不可绕过的审计日志，且审计返回值被丢弃、调用方无法
 *   关闭审计开关。这使命令执行在真实运营中必然留下可追溯记录——攻击者无法在
 *   不被检测的前提下隐蔽利用，故判 SAFE。
 *
 *   检测压力语义要点：VULN 侧审计"仅作观察"（可被规避），仍判 VULN；SAFE 侧审计
 *   "强制不可绕过"（记录 + 返回值丢弃不可控），使漏洞在运营层面不可隐蔽利用，判 SAFE。
 *
 * 修复要点（对照 VULN 侧 DetectionCmdAuditLog.java）：
 *   修复 = 让审计成为不可绕过约束：日志内容不可由调用方关闭、审计返回状态不可被
 *   调用方篡改、写入失败即中断执行。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class DetectionCmdForcedAudit {

    private static final Logger logger = Logger.getLogger(DetectionCmdForcedAudit.class.getName());
    private static final boolean AUDIT_ENFORCED = true;   // 审计开关不可由调用方关闭

    /**
     * 执行用户输入的命令，sink 前有强制不可绕过审计。
     *
     * @param userInput 用户可控的命令
     */
    public void exec(String userInput) {
        // 安全节点：强制审计，返回值被丢弃、开关不可控 —— 命令执行必然留痕
        forcedAudit(userInput);
        // [CHECKPOINT id=JSEF-DE-001S cwe=78 level=L2 source=userInput sink=runGuarded(cmd) after enforced non-bypassable audit expect=SAFE]
        runGuarded(userInput);                          // 安全 sink：被强制审计保护的命令执行
    }

    /**
     * 强制审计：命令 + 调用方写入审计日志，返回状态被丢弃（调用方不可控）。
     */
    static void forcedAudit(String cmd) {
        if (!AUDIT_ENFORCED) {
            return;                                     // 编译期恒真，实际永不返回
        }
        logger.warning("FORCED-AUDIT cmd-exec by DetectionCmdForcedAudit: " + cmd);
        // 语义等价：写入 WORM/追加式审计存储；写失败即抛异常中断执行
    }

    // 安全 sink：语义等价 Runtime.getRuntime().exec(cmd)，但已被强制审计保护
    static void runGuarded(String cmd) {
        System.out.println("[cmd-exec-audited] " + cmd);
    }
}
