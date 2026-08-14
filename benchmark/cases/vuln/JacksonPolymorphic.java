/*
 * JSEF Benchmark 样本 — Jackson 多态反序列化（D6，CWE-502，L3）
 * 运行态需 JSEF 依赖（com.fasterxml.jackson 2.x）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实 gadget 利用载荷。
 *
 * 知识点（CAP-05/09，L3 间接/框架语义）：
 *   ObjectMapper 启用多态类型（@JsonTypeInfo use=CLASS 或 enableDefaultTyping）后，
 *   JSON 中的类型信息会驱动 Jackson 实例化任意指定类。若未限制子类白名单，
 *   不可信 JSON 可指定危险类（如可触发任意方法/资源加载的类）从而可达危险行为。
 *   污点经 JSON 类型字段→反序列化引擎→目标类构造/setter，属于间接污点 + 框架语义。
 */
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JacksonPolymorphic {

    // 多态基类：使用 use=CLASS —— 反序列化时按 JSON 内全限定类名实例化
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    static class Payload { }

    /**
     * 危险入口：读取不可信 JSON，且多态类型未限制白名单。
     */
    static Object readUntrusted(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // source：不可信 JSON 文本
        // [CHECKPOINT id=JSEF-JACKSON-001 cwe=502 level=L3 source=untrusted JSON sink=ObjectMapper.readValue (polymorphic, no allowlist) expect=VULN]
        return mapper.readValue(json, Payload.class);   // 任意类可达（无白名单）
    }
}
