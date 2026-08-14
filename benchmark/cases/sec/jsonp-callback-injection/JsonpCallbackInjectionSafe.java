// [SAFE]
// 安全对照：JSONP 回调注入（修复版）
// 修复原则：严格校验回调函数名（仅允许 [A-Za-z0-9_]+），白名单过滤；设置正确 Content-Type。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：仅允许合法标识符作为 callback 名，拒绝注入。
 */
@RestController
@RequestMapping("/benchmark/sec/jsonp-injection")
public class JsonpCallbackInjectionSafe {

    // 仅允许的回调函数名白名单（演示用）
    private static final java.util.Set<String> ALLOWED = java.util.Set.of("callback", "handleResponse", "onData");

    /**
     * 安全示例：校验 callback 是否为合法标识符且位于白名单。
     */
    @GetMapping("/safe/direct-callback-concat")
    public String safeDirectCallbackConcat(String callback) {
        // 安全实践：白名单 + 格式校验，杜绝脚本注入
        // [CHECKPOINT id=JSEF-JSONP-001S cwe=352 level=L1 source=callback sink=response body (allowlist-validated callback, no injection) expect=SAFE]
        if (callback == null || !callback.matches("^[A-Za-z_][A-Za-z0-9_]*$") || !ALLOWED.contains(callback)) {
            return "{\"error\":\"invalid callback\"}";
        }
        return callback + "({'msg':'success'})";
    }
}
