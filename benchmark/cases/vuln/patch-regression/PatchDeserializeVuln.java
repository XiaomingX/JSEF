// [VULN]
package com.jsef.benchmark.vuln.patchregression;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DefaultTyping;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 2
 * 主题：反序列化放开 autotype 任意类 (CWE-502，难度 L4)
 *
 * 反模式：JSON 解析启用默认类型化，不可信 JSON 的 @class 可指定任意类，
 * 形成任意类反序列化 gadget 链可达性。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   原代码 activateDefaultTyping(EVERYTHING) 允许反序列化任意类型，攻击者可在 JSON 中
 *   指定 @class 触发危险 gadget（如 TemplatesImpl 命令执行）。
 *   修复方案（见 sec）：应改用类型白名单（JsonTypeInfo.Id.NAME + 显式 registerSubtypes），
 *   且白名单中绝不可包含 TemplatesImpl 等可命令执行类。
 *
 * 安全底线：仅 localhost 演示语义，不提供 gadget payload，不生成针对真实目标的工具。
 */
public class PatchDeserializeVuln {

    /**
     * 危险：全类型默认类型化，不可信 JSON 中 @class 可指定任意类。
     */
    static Object fromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(
            mapper.getPolymorphicTypeValidator(), DefaultTyping.EVERYTHING); // 危险：全类型
        // [CHECKPOINT id=JSEF-PR-002 cwe=502 level=L4 source=untrusted json sink=ObjectMapper.readValue with default typing expect=VULN]
        return mapper.readValue(json, Object.class); // @class 可指定任意类 -> gadget 可达
    }
}
