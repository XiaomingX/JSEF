package com.jsef.benchmark.vuln.dbg;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;

/**
 * DBG-1 Parser/Format Negotiation (RPC 机制 DBG 原子范式)
 *
 * 对应 CVE-2023-23638 抽象：请求中携带「使用哪种解析器/序列化格式」的指示，
 * 攻击者可借此将服务端切换到危险的反序列化格式。
 * 本文件与任何具体 RPC 框架完全解耦，仅用 Java 标准库自包含演示。
 * 仅用于 localhost 演示语义，不连接真实远端，不提供可利用的载荷脚本。
 */
public class DBG1_ParserNegotiation {

    /** 请求信封：携带 data 与 format 指示字段 */
    public static class Envelope {
        public String format; // 客户端可控制的格式指示
        public byte[] data;
    }

    // ============ L2：单方法内格式切换 ============

    /**
     * L2 多跳：攻击者控制 envelope.format，服务端据此选择解析路径。
     * format == "safe" 走 JSON 解析，否则走危险的反序列化。
     */
    public void handle(Envelope env) throws Exception {
        if (env.format.equals("safe")) {
            parseJson(env.data);
        } else {
            // [VULN] 攻击者指定非 safe 格式即可触发危险反序列化
            // [CHECKPOINT id=JSEF-DBG-101 cwe=502 level=L2 source=envelope.format field sink=ObjectInputStream.readObject (format switched) expect=VULN]
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(env.data));
            ois.readObject();
        }
    }

    private void parseJson(byte[] data) {
        // localhost-demo：安全的 JSON 解析占位
        new String(data, StandardCharsets.UTF_8);
    }

    // ============ L4：跨阶段格式切换（单文件内模拟跨阶段） ============

    /**
     * CVE-2023-23638 风格：请求中的协议/配置字段启用危险反序列化器。
     * StageA 解析出 format 指示存入上下文；StageC 依据该 format 选择解析器执行。
     * 两阶段之间 format 指示被隐式传递，攻击者可跨阶段注入危险格式。
     */

    /** 服务端上下文（承载跨阶段传递的 format 指示） */
    public static class RequestContext {
        public String negotiatedFormat;
    }

    private RequestContext ctx = new RequestContext();

    /** StageA：解析出 format 指示并写入上下文 */
    public void parseStageA(Envelope env) {
        // [VULN] 服务端信任请求中的格式指示并缓存在上下文
        // 行A：format 指示解析点
        ctx.negotiatedFormat = env.format;
    }

    /** StageC：依据上下文中的 format 选择解析器执行 */
    public void dispatchStageC(byte[] data) throws Exception {
        String format = ctx.negotiatedFormat;
        if (!"safe".equals(format)) {
            // [VULN] 跨阶段传递的危险 format 触发反序列化
            // [CHECKPOINT id=JSEF-DBG-102 cwe=502 level=L4 source=envelope.format (cross-stage) sink=ObjectInputStream.readObject expect=VULN trace=benchmark/cases/vuln/dbg/DBG1_ParserNegotiation.java:64,benchmark/cases/vuln/dbg/DBG1_ParserNegotiation.java:74]
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            ois.readObject();
        } else {
            parseJson(data);
        }
    }
}
