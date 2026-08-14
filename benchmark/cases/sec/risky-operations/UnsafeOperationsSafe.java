// [SAFE]
// 安全对照：高风险操作（修复版）
// 修复原则：生产环境严禁直接使用 sun.misc.Unsafe 与任意内存读写；本示例完全移除
//          用户输入到内存地址/Unsafe 的流向，提供安全的受信任操作替代。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 安全示例：不使用 Unsafe，内存访问相关能力以受信任的安全 API 替代。
 */
@RestController
@RequestMapping("/benchmark/sec/unsafe-operations")
public class UnsafeOperationsSafe {

    /**
     * 安全示例：读取配置/状态时不再允许用户指定任意内存地址，改用受信任来源。
     */
    @GetMapping("/safe/read-config")
    public String safeReadConfig(@RequestParam(required = false) String key) {
        // 安全实践：不接收内存地址，不存在 Unsafe.getInt(任意地址) 的危险 sink
        // [CHECKPOINT id=JSEF-RISKY-001S cwe=111 level=L1 source=@RequestParam key sink=no Unsafe memory access (untrusted input rejected) expect=SAFE]
        if (key == null || key.isEmpty()) {
            return "{\"status\":\"error\",\"message\":\"请提供配置键\"}";
        }
        return "{\"status\":\"ok\",\"key\":\"" + key + "\",\"value\":\"trusted-config\"}";
    }
}
