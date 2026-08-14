// [VULN]
// 漏洞样本：JSONP 回调注入——通过格式化拼接未校验 callback
// 漏洞点：callback 参数未校验直接拼入响应，可注入脚本。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;

/**
 * 不安全示例：格式化拼接未校验的 callback。
 */
@RestController
@RequestMapping("/benchmark/vuln/jsonp-callback-injection")
public class JsonpCallbackInjectionVulnB {

    /**
     * 不安全示例：String.format 拼接未校验 callback。
     */
    @GetMapping("/unsafe/format-callback-concat")
    public String unsafeFormatCallbackConcat(String callback) {
        // 危险实践：未校验 callback，直接拼入响应
        // [CHECKPOINT id=JSEF-JSONP-002 cwe=352 level=L1 source=callback sink=response body (format callback concat) expect=VULN]
        return String.format("%s({'msg':'success'})", callback);
    }
}
