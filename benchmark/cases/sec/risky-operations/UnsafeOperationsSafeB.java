// [SAFE]
// 安全对照：高风险内存写入操作（修复版）
// 修复原则：不使用 sun.misc.Unsafe 进行任意内存写入；相关能力以受信任 API 替代。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;

/**
 * 安全示例：移除 Unsafe.putInt 任意写入 sink。
 */
@RestController
@RequestMapping("/benchmark/sec/risky-operations")
public class UnsafeOperationsSafeB {

    /**
     * 安全示例：写配置不再允许用户指定内存地址。
     */
    @GetMapping("/safe/set-config")
    public String safeSetConfig(@RequestParam String key, @RequestParam String value) {
        // 安全实践：不存在 Unsafe.putInt(任意地址) 危险 sink
        // [CHECKPOINT id=JSEF-RISKY-002S cwe=111 level=L1 source=@RequestParam key,value sink=no Unsafe.putInt (untrusted input rejected) expect=SAFE]
        if (key == null || key.isEmpty()) {
            return "{\"status\":\"error\"}";
        }
        return "{\"status\":\"ok\",\"key\":\"" + key + "\"}";
    }
}
