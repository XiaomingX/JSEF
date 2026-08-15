/*
 * JSEF Benchmark 样本 — STR-2 Protocol/Metadata-layer Injection（CWE-917，协议层注入）
 *
 * 维度抽象：从「协议/元数据层字段被当表达式解析」这一类历史漏洞中抽象出的
 * 「表达式机制 STR」原子范式，与任何具体 Web 框架完全解耦。本文件演示「协议/元数据层
 * 字段」流入表达式引擎：
 *  - L3：HTTP Content-Type 头（协议层元数据字段）—— 非业务参数，属协议层元数据；
 *  - L4：路径段 / action 名（URL 路由标识）—— 非 @RequestParam 业务参数。
 * 二者本应只当元数据/路由标识，却被当表达式送入求值引擎 => 注入。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本，不连真实远端。
 * 危险调用以 "localhost-demo" 占位。
 */

package com.jsef.benchmark.vuln.str;

import com.sun.net.httpserver.HttpExchange;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class STR2_ProtocolLayerInjection {

    // ------------------------------------------------------------------
    // L3 维度：HTTP Content-Type 头（协议层字段）流入表达式引擎
    // 对应历史案例：Content-Type 被当表达式解析（协议层字段注入）。
    // ------------------------------------------------------------------

    // [VULN] HTTP 协议层头字段被当表达式求值
    static Object handle(HttpExchange exch) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");

        // [VULN] 取协议层头（Content-Type），非业务参数
        String headerValue = exch.getRequestHeaders().getFirst("Content-Type");  // 取协议层头（行1）

        // [VULN] 协议层头值直接送入表达式引擎
        // [CHECKPOINT id=JSEF-STR-201 cwe=917 level=L3 source=HTTP Content-Type header (protocol-layer) sink=evaluate(headerValue) expect=VULN trace=benchmark/cases/vuln/str/STR2_ProtocolLayerInjection.java:32,benchmark/cases/vuln/str/STR2_ProtocolLayerInjection.java:36]
        return engine.eval(headerValue);                              // 协议层头流入求值（行2）=> 注入
    }

    // ------------------------------------------------------------------
    // L4 维度：路径段 / action 名（协议层字段）流入表达式引擎
    // 对应历史案例：action 名（URL 路径段）被当表达式解析（协议层字段注入）。
    // ------------------------------------------------------------------

    // [VULN] 路径段 / action 名被当表达式求值
    static Object route(String pathSegment) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");

        // [VULN] 取路径段（action 名），非 @RequestParam 业务参数
        String action = pathSegment;                                  // 取路径段（行1）

        // [VULN] 路径段直接送入表达式引擎
        // [CHECKPOINT id=JSEF-STR-202 cwe=917 level=L4 source=path/action segment (protocol-layer) sink=evaluate(pathSegment) expect=VULN trace=benchmark/cases/vuln/str/STR2_ProtocolLayerInjection.java:49,benchmark/cases/vuln/str/STR2_ProtocolLayerInjection.java:53]
        return engine.eval(action);                                   // 路径段流入求值（行2）=> 注入
    }
}
