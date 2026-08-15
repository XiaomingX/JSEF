/*
 * JSEF Benchmark 安全样本 — 邀请奖励滥用（逻辑漏洞/会员，CWE-840，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：inviteCode 来自请求，但需防自邀与频率限制。
 *   ② 校验邀请人≠被邀人 + 频率/次数限制，杜绝刷奖。
 * 可达性说明：reward 先校验 inviter≠invitee 且未超发奖次数上限，满足才发奖。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实刷奖利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 vuln）：校验邀请人≠被邀人 + 频率/次数限制。
 */
package com.jsef.benchmark.sec.logic;

import java.util.Map;

public class InviteRewardAbuse_Safe {

    static final Map<String, Integer> REWARD_COUNT = new java.util.HashMap<>();
    static final int MAX_REWARD = 5;

    /**
     * 安全入口：防自邀 + 次数限制。
     */
    public boolean reward(String inviter, String invitee) {
        if (inviter.equals(invitee)) {            // 防自邀
            return false;
        }
        int used = REWARD_COUNT.getOrDefault(inviter, 0);
        if (used >= MAX_REWARD) {                 // 频率/次数限制
            return false;
        }
        // [CHECKPOINT id=JSEF-MEM-002S cwe=840 level=L3 source=inviteCode sink=issueReward after self-invite/rate-limit check expect=SAFE]
        issueReward(inviter, invitee);            // 仅合规发奖
        REWARD_COUNT.put(inviter, used + 1);
        return true;
    }

    static void issueReward(String inviter, String invitee) { /* 演示：发奖，无副作用 */ }
}
