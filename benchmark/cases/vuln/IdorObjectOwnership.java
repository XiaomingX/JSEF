/*
 * JSEF Benchmark 样本 — IDOR / 越权访问（D5，CWE-639，L4）
 * 运行态需 JSEF 依赖（Spring Data JPA 等）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实越权利用脚本。
 *
 * 知识点（CAP-07/08/09，L4 业务语义依赖）：
 *   漏洞核心不在"污点传播"，而在"业务归属语义"——攻击者传入任意对象 id，
 *   服务直接用 id 取数据返回，未校验"当前登录用户是否是该对象拥有者"。
 *   这是 OWASP A01 失效访问控制的典型：数据流干净，但授权缺失。
 *   静态分析需在 repo.findById(id) 的返回处识别"缺少 owner 校验"这一状态机前提。
 */
import java.util.Optional;

public class IdorObjectOwnership {

    // 演示用：当前登录用户（运行态来自 Spring Security 上下文）
    static final class User { final String id; User(String id){ this.id = id; } }
    static final class Doc { final String id; final String ownerId; final String content;
        Doc(String id, String ownerId, String content){ this.id=id; this.ownerId=ownerId; this.content=content; } }

    // 演示用仓储接口（语义同 Spring Data JPA CrudRepository）
    interface DocRepository { Optional<Doc> findById(String id); }

    /**
     * 危险入口：用请求传入的 id 直接取文档返回，未校验归属。
     */
    static Doc getDocument(DocRepository repo, String id, User currentUser) {
        // source：不可信 id（HTTP 参数，攻击者可控）
        // [CHECKPOINT id=JSEF-IDOR-001 cwe=639 level=L4 source=user-controlled id sink=repo.findById(id) (no owner check) expect=VULN]
        return repo.findById(id).orElseThrow();   // 越权：任意 id 可读他人文档
    }
}
