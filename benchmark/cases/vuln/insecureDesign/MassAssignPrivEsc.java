/*
 * JSEF Benchmark 样本 — 批量赋值提权（A04，CWE-915，L3）
 * 运行态需 JSEF 依赖（Spring MVC / Jackson）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实提权利用。
 *
 * 知识点（A04 不安全设计，CWE-915 批量赋值）：
 *   直接将请求体 JSON 绑定到含特权字段（isAdmin）的实体类，攻击者在 JSON 中加 "isAdmin":true
 *   即可自提权。正确设计应使用仅含白名单字段的 DTO。数据流：JSON → 实体绑定（含 isAdmin）。
 */
public class MassAssignPrivEsc {

    static class UserProfile { String username; boolean isAdmin; }   // 含特权字段

    /**
     * 危险入口：JSON 直绑实体（含 isAdmin）。
     */
    static UserProfile bind(String username, boolean isAdmin) {
        UserProfile p = new UserProfile();
        p.username = username;
        // [CHECKPOINT id=JSEF-A04-002 cwe=915 level=L3 source=@RequestBody JSON sink=UserProfile.isAdmin bind expect=VULN]
        p.isAdmin = isAdmin;   // 越权：攻击者可在 JSON 中注入 isAdmin=true
        return p;
    }
}
