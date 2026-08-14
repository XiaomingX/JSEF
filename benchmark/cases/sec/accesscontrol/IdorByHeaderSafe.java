/*
 * JSEF Benchmark 安全样本 — IDOR 通过 HTTP Header（A01，CWE-639，L3）
 * SAFE 版：从 Header 取资源 id 后，先校验归属再返回。
 * 测试点：强 SAST/LLM 应识别已完成 owner 校验而不报（TN）；弱工具易误报。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import java.util.Optional;

public class IdorByHeaderSafe {

    static final class User { final String id; User(String id){ this.id = id; } }
    static final class Record { final String id; final String ownerId; final String data;
        Record(String id, String ownerId, String data){ this.id=id; this.ownerId=ownerId; this.data=data; } }

    interface RecordRepository { Optional<Record> findById(String id); }

    /**
     * 安全入口：取资源后立即校验归属。
     */
    static Record getRecord(RecordRepository repo, String resourceIdHeader, User currentUser) {
        Record rec = repo.findById(resourceIdHeader).orElseThrow();
        // 归属校验：阻断越权
        // [CHECKPOINT id=JSEF-A01-002S cwe=639 level=L3 source=HTTP Header X-Resource-Id sink=if(!owner.equals) throw 403 expect=SAFE]
        if (!rec.ownerId.equals(currentUser.id)) {
            throw new SecurityException("403 forbidden: not owner");
        }
        return rec;
    }
}
