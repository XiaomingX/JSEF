/*
 * JSEF Benchmark 安全样本 — 会员等级篡改（逻辑漏洞/会员，CWE-285 授权不当，L3）
 *
 * 子目标清单：
 *   ① 识别客户端可控关键业务参数：前端不再传 membershipLevel，权益必须以服务端真实等级为准。
 *   ② 权益由服务端会话中的真实等级决定，客户端无法伪造。
 * 可达性说明：grantBenefit 从服务会话取真实等级，忽略任何客户端等级字段，污点不抵授权 sink。
 * 安全底线声明：本样本仅 localhost 演示语义，不写真实越权利用脚本，不生成针对真实目标工具。
 * 修复要点（对照 vuln）：权益由服务端会话中的真实等级决定。
 */
package com.jsef.benchmark.sec.logic;

public class MembershipLevelTamper_Safe {

    /**
     * 安全入口：权益由服务端会话中的真实等级决定。
     */
    public String grantBenefit(String userId, Session session) {
        String realLevel = session.getRealMembershipLevel(userId);  // 服务端真实等级
        // [CHECKPOINT id=JSEF-MEM-001S cwe=285 level=L3 source=server session real level sink=grantByLevel(realLevel) expect=SAFE]
        return grantByLevel(realLevel);            // 客户端等级被忽略
    }

    static String grantByLevel(String level) { return "benefit:" + level; }

    interface Session { String getRealMembershipLevel(String userId); }
}
