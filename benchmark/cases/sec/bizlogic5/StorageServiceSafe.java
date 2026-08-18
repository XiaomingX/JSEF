// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 存储服务（安全版）：忽略用户 mode，强制降权。
 *
 * 评分约定：SAFE 侧按实现判定。本方法体真实实现了权限白名单/降权。
 */
public class StorageServiceSafe {

    private final FilePermissionGatewaySafe permissionGateway;

    public StorageServiceSafe(FilePermissionGatewaySafe permissionGateway) {
        this.permissionGateway = permissionGateway;
    }

    public String store(String name, String content, String requestedMode) {
        // 真实实现降权：忽略用户请求，固定为安全权限
        String safeMode = "0644"; // 仅属主可写，其他只读
        // [CHECKPOINT id=JSEF-BIZ5-732-002S cwe=732 level=L5 source=ignored user mode sink=FilePermissionGatewaySafe.apply expect=SAFE trace=benchmark/cases/sec/bizlogic5/FileUploadControllerSafe.java:26,benchmark/cases/sec/bizlogic5/FilePermissionGatewaySafe.java:9]
        return permissionGateway.apply(name, safeMode);
    }
}
