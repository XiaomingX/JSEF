// [SAFE]
// 安全对照：JSONP 回调注入（格式化拼接，修复版）
// 修复原则：校验 callback 为合法标识符/白名单，拒绝注入。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：格式化拼接前校验 callback。
 */
@RestController
@RequestMapping("/benchmark/sec/jsonp-callback-injection")
public class JsonpCallbackInjectionSafeB {

    private static final java.util.Set<String> ALLOWED = java.util.Set.of("callback", "handleResponse");

    /**
     * 安全示例：白名单 + 格式校验。
     */
    @GetMapping("/safe/format-callback-concat")
    public String safeFormatCallbackConcat(String callback) {
        // 安全实践：校验通过才拼接
        // [CHECKPOINT id=JSEF-JSONP-002S cwe=352 level=L1 source=callback sink=response body (allowlist-validated callback) expect=SAFE]
        if (callback == null || !callback.matches("^[A-Za-z_][A-Za-z0-9_]*$") || !ALLOWED.contains(callback)) {
            return "{\"error\":\"invalid callback\"}";
        }
        return String.format("%s({'msg':'success'})", callback);
    }
}
