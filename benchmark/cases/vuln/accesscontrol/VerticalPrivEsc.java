/*
 * JSEF Benchmark 样本 — 垂直越权/提权（A01，CWE-285，L4）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实提权利用脚本。
 *
 * 知识点（A01 失效访问控制，CWE-285 授权错误）：
 *   用户提交的数据中携带 role 字段（如 "ADMIN"），服务端直接信任该字段并据此赋予权限，
 *   未校验"当前用户是否真的具备该角色"。普通用户可通过篡改 role 实现垂直提权。
 *   这是框架绑定语义 + 授权缺失的组合：数据流经 @ModelAttribute 绑定 role，但授权校验缺失。
 */
public class VerticalPrivEsc {

    static final class Account { String username; String role; }

    /**
     * 危险入口：直接从请求体绑定 role 并据此授权，未校验真实角色。
     */
    static boolean isAdmin(Account account) {
        // source：不可信 role（HTTP 请求体绑定，攻击者可控）
        // [CHECKPOINT id=JSEF-A01-003 cwe=285 level=L4 source=request-bound role field sink=authorization decision on role expect=VULN]
        return "ADMIN".equals(account.role);   // 越权：普通用户伪造 ADMIN 即提权
    }
}
