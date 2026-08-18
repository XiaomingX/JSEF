// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 修复版：Correct Permission Assignment (CWE-732 修复)
 *
 * 差异：StorageService 忽略用户 mode，强制降权为安全默认值（0644）。
 */
@RestController
public class FileUploadControllerSafe {

    private final StorageServiceSafe storageService;

    public FileUploadControllerSafe(StorageServiceSafe storageService) {
        this.storageService = storageService;
    }

    @PostMapping("/api/v1/files/upload")
    public String upload(@RequestParam("name") String name,
                         @RequestParam("content") String content,
                         @RequestParam("mode") String mode) {
        // 安全：用户提交的 mode 被忽略，内部强制安全权限
        // [CHECKPOINT id=JSEF-BIZ5-732-001S cwe=732 level=L5 source=@RequestParam mode sink=StorageServiceSafe.store expect=SAFE trace=benchmark/cases/sec/bizlogic5/StorageServiceSafe.java:20,benchmark/cases/sec/bizlogic5/FilePermissionGatewaySafe.java:9]
        return storageService.store(name, content, mode);
    }
}
