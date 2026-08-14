// [VULN]
// 漏洞样本：高风险操作——通过 Unsafe 向任意内存地址写入数据
// 漏洞点：用户指定地址与值，直接调用 unsafe.putInt 写入任意内存。
package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.*;
import sun.misc.Unsafe;
import java.lang.reflect.Field;

/**
 * 不安全示例：允许向任意内存地址写入。
 */
@RestController
@RequestMapping("/benchmark/vuln/risky-operations")
public class UnsafeOperationsVulnB {

    private static final Unsafe unsafe;

    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafe = (Unsafe) f.get(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 不安全示例：用户可控地址与值，直接写内存。
     */
    @GetMapping("/unsafe/write-memory")
    public String unsafeWriteMemory(@RequestParam Long targetAddress, @RequestParam Integer valueToWrite) {
        // 危险实践：用户可控地址写入
        // [CHECKPOINT id=JSEF-RISKY-002 cwe=111 level=L1 source=@RequestParam targetAddress,valueToWrite sink=Unsafe.putInt (arbitrary memory write) expect=VULN]
        unsafe.putInt(targetAddress, valueToWrite);
        return "{\"status\":\"danger\",\"message\":\"已写入内存\"}";
    }
}
