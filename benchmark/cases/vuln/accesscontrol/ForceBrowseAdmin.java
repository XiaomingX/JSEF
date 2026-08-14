/*
 * JSEF Benchmark 样本 — 强制浏览 admin 接口（A01，CWE-285，L4）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点（A01 失效访问控制，CWE-285 授权错误）：
 *   管理接口（如 /api/admin/config）无任何权限判断，只要知道 URL 即可直接访问。
 *   服务端未检查调用者是否为管理员，导致任意登录用户甚至匿名用户可强制浏览受限接口。
 *   数据流干净但授权缺失，属典型 OWASP A01 强制浏览（forced browsing）。
 */
public class ForceBrowseAdmin {

    static final class Session { final boolean isAdmin; Session(boolean isAdmin){ this.isAdmin=isAdmin; } }

    /**
     * 危险入口：admin 接口未做权限判断直接返回敏感配置。
     */
    static String adminConfig(Session session) {
        // source：请求直达 admin 接口；sink：返回配置，无 isAdmin 校验
        // [CHECKPOINT id=JSEF-A01-005 cwe=285 level=L4 source=direct request to /admin sink=return admin config (no isAdmin check) expect=VULN]
        return "sensitive-admin-config";   // 越权：任意用户可强制浏览 admin 接口
    }
}
