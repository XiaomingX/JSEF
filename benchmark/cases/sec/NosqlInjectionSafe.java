/*
 * JSEF Benchmark 真假混淆样本 — NoSQL 安全查询（D3，CWE-943，L3）
 * SAFE 版：使用类型安全 Criteria 且字段名来自白名单常量，用户值仅作为字面量比较。
 * 测试点：弱 SAST/LLM 易将"用了 Mongo 查询 + 用户输入"误报为 NoSQL 注入（测 FP）。
 * 运行态需 JSEF 依赖（Spring Data Mongo）；独立 benchmark 源文件，不强求编译。
 */
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import java.util.Set;

public class NosqlInjectionSafe {

    // 仅允许查询的字段白名单（受控常量）
    static final Set<String> ALLOWED_FIELDS = Set.of("username", "email");

    /**
     * 安全入口：字段名白名单校验，值仅作字面量相等比较。
     */
    static Iterable<Document> safeQuery(MongoDatabase db, String userField, String userValue) {
        MongoCollection<Document> coll = db.getCollection("users");
        // 字段名必须命中白名单，用户值不再被当作操作符解析
        if (!ALLOWED_FIELDS.contains(userField)) {
            throw new IllegalArgumentException("field not allowed: " + userField);
        }
        Document filter = new Document(userField, userValue); // 类型安全：值即字面量
        // [CHECKPOINT id=JSEF-NOSQL-001S cwe=943 level=L3 source=query param sink=MongoCollection.find expect=SAFE]
        return coll.find(filter); // 已受控，无 NoSQL 注入
    }
}
