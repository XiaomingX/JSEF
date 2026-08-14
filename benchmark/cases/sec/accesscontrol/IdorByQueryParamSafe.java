/*
 * JSEF Benchmark 安全样本 — IDOR 通过查询参数（A01，CWE-639，L3）
 * SAFE 版：在返回资源前显式校验"当前登录用户是否为资源拥有者"，否则抛 403。
 * 测试点：强 SAST/LLM 应识别此处已做归属校验而不报（TN）；弱工具易误报（测 FP）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import java.util.Optional;

public class IdorByQueryParamSafe {

    static final class User { final String id; User(String id){ this.id = id; } }
    static final class Record { final String id; final String ownerId; final String data;
        Record(String id, String ownerId, String data){ this.id=id; this.ownerId=ownerId; this.data=data; } }

    interface RecordRepository { Optional<Record> findById(String id); }

    /**
     * 安全入口：取资源后立即校验归属。
     */
    static Record getRecord(RecordRepository repo, String id, User currentUser) {
        Record rec = repo.findById(id).orElseThrow();
        // 归属校验：阻断越权
        // [CHECKPOINT id=JSEF-A01-001S cwe=639 level=L3 source=@RequestParam id sink=if(!owner.equals) throw 403 expect=SAFE]
        if (!rec.ownerId.equals(currentUser.id)) {
            throw new SecurityException("403 forbidden: not owner");
        }
        return rec;
    }
}
