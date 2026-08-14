/*
 * JSEF Benchmark 样本 — IDOR 通过 HTTP Header（A01，CWE-639，L3）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实越权利用脚本。
 *
 * 知识点（A01 失效访问控制）：
 *   与 IdorByQueryParam 同理，但资源 id 来自自定义 HTTP Header（如 X-Resource-Id）而非查询参数。
 *   Header 同样不可信，服务端直接用其取数据返回，未校验归属。数据流干净但授权缺失。
 */
import java.util.Optional;

public class IdorByHeader {

    static final class User { final String id; User(String id){ this.id = id; } }
    static final class Record { final String id; final String ownerId; final String data;
        Record(String id, String ownerId, String data){ this.id=id; this.ownerId=ownerId; this.data=data; } }

    interface RecordRepository { Optional<Record> findById(String id); }

    /**
     * 危险入口：从 Header 取资源 id 直查返回，无归属校验。
     */
    static Record getRecord(RecordRepository repo, String resourceIdHeader, User currentUser) {
        // source：不可信 resourceId（HTTP Header，攻击者可控）
        // [CHECKPOINT id=JSEF-A01-002 cwe=639 level=L3 source=HTTP Header X-Resource-Id sink=repo.findById(resourceId) (no owner check) expect=VULN]
        return repo.findById(resourceIdHeader).orElseThrow();   // 越权：任意 id 可读他人记录
    }
}
