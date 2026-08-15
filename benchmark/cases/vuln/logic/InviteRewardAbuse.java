/*
 * JSEF Benchmark 样本 — 邀请奖励滥用（逻辑漏洞/会员，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：inviteCode 来自 @RequestParam，缺防自邀/频率限制。
 *   ② 攻击者可用自己邀请码自邀或无限刷奖励。
 * 可达性说明：reward 直接按 inviteCode 发奖，未校验邀请人≠被邀人，也无频率/次数限制，
 *   污点（客户端邀请码）直达发奖 sink 且无校验。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实刷奖利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 sec）：校验邀请人≠被邀人 + 频率/次数限制。
 */
package com.jsef.benchmark.vuln.logic;

public class InviteRewardAbuse {

    /**
     * 危险入口：inviteCode 直接取 @RequestParam，无限制发奖。
     */
    public boolean reward(String inviter, String invitee,
                          @RequestParamLike String inviteCode) {
        // 邀请码读取行：客户端可控 inviteCode 进入作用域（source 抵达）
        String code = inviteCode;                 // 行22：参数读取（source 抵达）

        // [CHECKPOINT id=JSEF-MEM-002 cwe=840 level=L3 source=@RequestParam inviteCode sink=issueReward(inviter,invitee) (no self-invite/rate limit) expect=VULN trace=benchmark/cases/vuln/logic/InviteRewardAbuse.java:22,benchmark/cases/vuln/logic/InviteRewardAbuse.java:26]
        // 无限制发奖行：未校验邀请人≠被邀人，也无频率/次数限制
        issueReward(inviter, invitee);            // 行26：缺陷点（可自邀/无限刷）
        return true;
    }

    static void issueReward(String inviter, String invitee) { /* 演示：发奖，无副作用 */ }

    @interface RequestParamLike {}
}
