/*
 * JSEF Benchmark 真假混淆样本 — Jackson 多态安全版（D6，CWE-502，L3）
 * SAFE 版：用 activateDefaultTyping + 白名单 PolymorphicTypeValidator，或 @JsonTypeInfo use=NAME 限定已知子类。
 * 测试点：强 SAST/LLM 应识别已做白名单/NAME 限定而不报；弱工具易误报（测 FP）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

public class JacksonPolymorphicSafe {

    // 仅允许已知子类，用 NAME 而非 CLASS
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
    @JsonSubTypes({
        @JsonSubTypes.Type(value = Foo.class, name = "foo"),
        @JsonSubTypes.Type(value = Bar.class, name = "bar")
    })
    static class Payload { }
    static class Foo extends Payload { }
    static class Bar extends Payload { }

    /**
     * 安全入口：白名单校验的默认类型 + 限定子类。
     */
    static Object readUntrusted(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // 白名单：仅允许 Payload 包下已知类型
        var ptv = BasicPolymorphicTypeValidator.builder()
                .allowIfSubType(Payload.class)
                .build();
        mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);
        // [CHECKPOINT id=JSEF-JACKSON-001S cwe=502 level=L3 source=untrusted JSON sink=ObjectMapper.readValue (allowlist + NAME) expect=SAFE]
        return mapper.readValue(json, Payload.class);   // 白名单内，不可达危险类
    }
}
