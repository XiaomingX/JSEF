/*
 * JSEF Benchmark 样本 — STR-2 Protocol/Metadata-layer Injection 安全对照（CWE-917）
 *
 * 修复策略：
 *  - L3：Content-Type 头只当元数据使用（如读取 MIME 类型），绝不进入表达式引擎。
 *  - L4：路径段 / action 名只当路由标识做精确匹配，绝不进入表达式引擎。
 * 若确需解析动态表达式，应走严格白名单，但协议层字段本身不应成为表达式源。
 *
 * 与任何具体 Web 框架完全解耦，仅用 Java 标准库。
 */

package com.jsef.benchmark.sec.str;

import com.sun.net.httpserver.HttpExchange;
import java.util.Set;

public class STR2_ProtocolLayerInjection_Safe {

    // 允许的 action 白名单（已知安全路由标识）
    private static final Set<String> ALLOWED_ACTIONS = Set.of("home", "login", "logout", "about");

    // ------------------------------------------------------------------
    // L3 修复：Content-Type 头只当元数据，不进表达式引擎
    // ------------------------------------------------------------------

    // [SAFE] 协议层头仅作元数据，从不送入求值器
    static String handleSafe(HttpExchange exch) {
        // [SAFE] 取 Content-Type 仅作元数据（MIME 类型判断）
        // [CHECKPOINT id=JSEF-STR-201S cwe=917 level=L3 source=Content-Type header sink=header as metadata only (no eval) expect=SAFE]
        String contentType = exch.getRequestHeaders().getFirst("Content-Type");  // 头只当元数据

        if (contentType == null) {
            return "localhost-demo: default";
        }
        // 仅用于内容协商，绝不 evaluate
        return "localhost-demo: content-type=" + contentType;        // 头值不进表达式引擎
    }

    // ------------------------------------------------------------------
    // L4 修复：路径段 / action 名只做路由匹配，不进表达式引擎
    // ------------------------------------------------------------------

    // [SAFE] 路径段仅作路由标识，从不送入求值器
    static String routeSafe(String pathSegment) {
        // [SAFE] 路径段只做精确白名单匹配，绝不 evaluate
        // [CHECKPOINT id=JSEF-STR-202S cwe=917 level=L4 source=path segment sink=no eval on protocol field expect=SAFE]
        if (!ALLOWED_ACTIONS.contains(pathSegment)) {                // 路径段仅路由匹配
            return "localhost-demo: 404";
        }
        return "localhost-demo: routed-to-" + pathSegment;           // 不进表达式引擎
    }
}
