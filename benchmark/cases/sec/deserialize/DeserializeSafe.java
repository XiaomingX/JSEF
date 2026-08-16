/*
 * JSEF Benchmark 样本 — 组件反序列化安全对照 (CWE-502, L3)
 * XStream 设类型白名单；Jackson 关闭默认类型；SnakeYAML 限定安全构造器。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DefaultTyping;
import org.yaml.snakeyaml.Yaml;
import java.util.List;

public class DeserializeSafe {

    static Object xstream(String xml) {
        XStream xs = new XStream();
        xs.addPermission(NoTypePermission.NONE); // 默认拒绝
        xs.allowTypes(new Class[]{String.class, java.util.ArrayList.class}); // 白名单
        // [CHECKPOINT id=JSEF-EXT-018S cwe=502 level=L3 source=untrusted xml sink=XStream with type allowlist expect=SAFE]
        return xs.fromXML(xml);
    }

    static Object jackson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper(); // 不启用默认类型
        // [CHECKPOINT id=JSEF-EXT-019S cwe=502 level=L3 source=untrusted json sink=ObjectMapper.readValue without default typing expect=SAFE]
        return mapper.readValue(json, Object.class);
    }

    static Object snakeYaml(String text) {
        Yaml yaml = new Yaml(); // 仅允许基础类型集合
        // [CHECKPOINT id=JSEF-EXT-020S cwe=502 level=L3 source=untrusted yaml sink=Yaml.load with safe types expect=SAFE]
        return yaml.load(text);
    }
}
