/*
 * JSEF Benchmark 样本 — Jackson activateDefaultTyping 不安全反序列化 (CWE-502, L3)
 * 启用默认类型化，不可信 JSON 中的 @class 可指定任意类。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DefaultTyping;

public class JacksonDefaultTyping {

    static Object fromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(
            mapper.getPolymorphicTypeValidator(), DefaultTyping.EVERYTHING); // 危险：全类型
        // [CHECKPOINT id=JSEF-EXT-019 cwe=502 level=L3 source=untrusted json sink=ObjectMapper.readValue with default typing expect=VULN]
        return mapper.readValue(json, Object.class); // @class 可指定任意类
    }
}
