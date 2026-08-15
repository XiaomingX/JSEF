/*
 * JSEF Benchmark 样本 — 会员等级篡改（逻辑漏洞/会员，CWE-285 授权不当，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：membershipLevel 来自 @RequestParam，服务端未校验该用户真实等级。
 *   ② 攻击者传高等级即可越权享受会员权益。
 * 可达性说明：grantBenefit 直接按客户端传入的 membershipLevel 授权益，未与会话中真实等级比对，
 *   污点（客户端等级）直达授权 sink 且无校验。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实越权利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 sec）：权益由服务端会话中的真实等级决定，忽略客户端等级参数。
 */
package com.jsef.benchmark.vuln.logic;

public class MembershipLevelTamper {

    /**
     * 危险入口：membershipLevel 直接取 @RequestParam，未校验真实等级。
     */
    public String grantBenefit(String userId,
                               @RequestParamLike String membershipLevel) {
        // 参数读取行：客户端可控 membershipLevel 进入作用域（source 抵达）
        String clientLevel = membershipLevel;     // 行22：参数读取（source 抵达）

        // [CHECKPOINT id=JSEF-MEM-001 cwe=285 level=L3 source=@RequestParam membershipLevel sink=grantByLevel(clientLevel) (no real-level check) expect=VULN trace=benchmark/cases/vuln/logic/MembershipLevelTamper.java:22,benchmark/cases/vuln/logic/MembershipLevelTamper.java:26]
        // 按客户端等级授权益行：直接以客户端等级发放权益，未比对真实等级
        return grantByLevel(clientLevel);         // 行26：缺陷点（未校验真实等级）
    }

    static String grantByLevel(String level) { return "benefit:" + level; }

    @interface RequestParamLike {}
}
