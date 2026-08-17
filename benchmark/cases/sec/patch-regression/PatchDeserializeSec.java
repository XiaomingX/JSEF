// [VULN]  — 注意：本文件是「回归副作用」对照 sec，补丁后仍不安全（expect=VULN）
package com.jsef.benchmark.sec.patchregression;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder;

/**
 * JSEF-Benchmark — C 类（端到端补丁回归副作用）样本 2 的对照
 * 主题：反序列化补丁「白名单含危险类」，修复不完整 (CWE-502，难度 L4)
 *
 * 反模式（真实安全工程反模式）：
 *   开发者看到 activateDefaultTyping(EVERYTHING) 会反序列化任意类，于是改成「类型白名单」。
 *   这是对的。但白名单里误把 com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
 *   这类「可被利用来命令执行」的类放进了允许列表 —— 旧的「任意类」风险表面收敛了，
 *   却留下「白名单内的危险 gadget 仍可达」的新漏洞（修复不完整）。
 *
 * 解释漏洞（须紧跟修复方案）：
 *   残留 sink：enabledForTypes 白名单包含 TemplatesImpl，攻击者在 JSON 中指定
 *   @class=TemplateImpls 并带恶意字节码即可命令执行。
 *   修复方案：白名单只放业务 DTO 类型，使用 JsonTypeInfo.Id.NAME + 显式 registerSubtypes，
 *   绝不放任何 JDK 内部可命令执行类。
 *
 * 安全底线：仅 localhost 演示语义，不提供 gadget payload，不生成针对真实目标的工具。
 *
 * 本 sec 文件 expect=VULN：补丁后白名单仍含危险类，被测工具应报。
 */
public class PatchDeserializeSec {

    /**
     * 看似修复：用了类型白名单，但白名单含可命令执行的 TemplatesImpl。
     */
    static Object fromJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        StdTypeResolverBuilder resolver = new StdTypeResolverBuilder()
            .init(JsonTypeInfo.Id.CLASS, null)
            .inclusion(JsonTypeInfo.As.PROPERTY)
            // 危险：白名单里包含可命令执行类 TemplatesImpl
            .withDefaultImpl(java.lang.Object.class);
        mapper.setDefaultTyping(resolver);

        // 允许列表（修复不完整）：把危险 gadget 类也放进去了
        String[] allowed = {
            "com.example.dto.Order",
            "com.example.dto.User",
            // [CHECKPOINT id=JSEF-PR-002S cwe=502 level=L4 source=untrusted json sink=ObjectMapper.readValue with dangerous class in allowlist expect=VULN]
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl" // 可命令执行的 gadget 类
        };
        // 语义等价：mapper.readValue(json, Object.class) 在 @class 命中 allowed 时实例化该类
        System.out.println("[deserialize] allowlist contains dangerous class: " + allowed[2]);
        return mapper.readValue(json, Object.class);
    }
}
