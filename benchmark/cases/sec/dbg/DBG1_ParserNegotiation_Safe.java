package com.jsef.benchmark.sec.dbg;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;

/**
 * DBG-1 Parser/Format Negotiation — 安全修复版
 *
 * 修复策略：解析格式由服务端固定（不读取请求字段），或格式→解析器走白名单
 * 且危险格式不在列。与任何具体 RPC 框架解耦，仅用 Java 标准库自包含演示。
 * 仅用于 localhost 演示语义。
 */
public class DBG1_ParserNegotiation_Safe {

    public static class Envelope {
        public String format; // 仍然存在于请求中，但服务端不再依据它选择解析器
        public byte[] data;
    }

    public static class RequestContext {
        public String negotiatedFormat;
    }

    // ============ L2：服务端固定解析格式（不读取请求字段） ============

    /**
     * L2 修复：无论请求中 format 为何，服务端始终使用安全的 JSON 解析。
     */
    public void handle(Envelope env) throws Exception {
        // [SAFE] 解析格式由服务端固定，客户端无法选择
        // [CHECKPOINT id=JSEF-DBG-101S cwe=502 level=L2 source=envelope sink=server-fixed format (no client choice) expect=SAFE]
        parseJson(env.data);
    }

    private void parseJson(byte[] data) {
        new String(data, StandardCharsets.UTF_8);
    }

    // ============ L4：跨阶段格式白名单（仅安全格式） ============

    private RequestContext ctx = new RequestContext();

    public void parseStageA(Envelope env) {
        // 服务端忽略请求中的 format 指示，仅按安全策略设定
        ctx.negotiatedFormat = "safe";
    }

    public void dispatchStageC(byte[] data) throws Exception {
        // [SAFE] 格式来自服务端白名单，危险格式永远不在列
        // [CHECKPOINT id=JSEF-DBG-102S cwe=502 level=L4 source=envelope sink=format allowlist (safe only) expect=SAFE]
        if ("safe".equals(ctx.negotiatedFormat)) {
            parseJson(data);
        }
        // 危险反序列化分支已被移除，不再可达
    }
}
