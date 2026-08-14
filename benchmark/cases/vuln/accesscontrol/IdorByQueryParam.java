/*
 * JSEF Benchmark 样本 — IDOR 通过查询参数（A01，CWE-639，L3）
 * 运行态需 JSEF 依赖（Spring MVC / Spring Data JPA）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实越权利用脚本。
 *
 * 知识点（A01 失效访问控制）：
 *   漏洞核心不在"污点传播"，而在"业务归属语义"——攻击者通过 @RequestParam 传入任意对象 id，
 *   Controller 直接用该 id 查询并返回资源，未校验"当前登录用户是否是该资源拥有者"。
 *   数据流干净（id 直接入查询），但授权缺失，属典型 OWASP A01。
 *   静态分析应在 repo.findById(id) 处识别"缺少 owner 校验"这一状态机前提。
 */
import java.util.Optional;

public class IdorByQueryParam {

    static final class User { final String id; User(String id){ this.id = id; } }
    static final class Record { final String id; final String ownerId; final String data;
        Record(String id, String ownerId, String data){ this.id=id; this.ownerId=ownerId; this.data=data; } }

    interface RecordRepository { Optional<Record> findById(String id); }

    /**
     * 危险入口：@RequestParam id 直查资源返回，无 owner 校验。
     */
    static Record getRecord(RecordRepository repo, String id, User currentUser) {
        // source：不可信 id（HTTP @RequestParam，攻击者可控）
        // [CHECKPOINT id=JSEF-A01-001 cwe=639 level=L3 source=@RequestParam id sink=repo.findById(id) (no owner check) expect=VULN]
        return repo.findById(id).orElseThrow();   // 越权：任意 id 可读他人记录
    }
}
