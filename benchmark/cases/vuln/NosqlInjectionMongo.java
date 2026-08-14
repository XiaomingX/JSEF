/*
 * JSEF Benchmark 样本 — NoSQL 注入（D3，CWE-943，L3 间接污点）
 * 运行态需 JSEF 依赖（MongoDB Driver / Spring Data Mongo）；独立 benchmark 源文件，
 * 使用标准 Mongo API 表达 sink，不强求编译。污点经 Map/BSON 间接传播。
 * 安全底线：仅 localhost 演示语义，不写真实注入 payload。
 */
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import java.util.Map;

public class NosqlInjectionMongo {

    /**
     * 危险入口：查询参数直接构造 BSON 过滤条件，经 Map 间接传播到 Mongo sink。
     */
    static Iterable<Document> query(MongoDatabase db, String userField, String userValue) {
        // source：不可信查询参数
        MongoCollection<Document> coll = db.getCollection("users");
        // 污点经 Map 间接传播： {field: value} 作为查询过滤器
        Map<String, Object> filterMap = Map.of(userField, userValue); // 间接污点起点：经 Map/BSON 中转
        Document filter = new Document(filterMap);                    // 污点经 BSON 中转
        // [CHECKPOINT id=JSEF-NOSQL-001 cwe=943 level=L3 source=query param sink=MongoCollection.find expect=VULN]
        return coll.find(filter); // NoSQL 注入可达（如 userField=$where / userValue={"$gt":""}）
    }
}
