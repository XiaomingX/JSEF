// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 存储服务（危险权限透传根因）。
 *
 * 语义等价：Files.write(...) 后 setPosixFilePermissions(...)。
 * 缺陷：store 把请求携带的 mode 原样传给权限网关，无降权/白名单。
 */
public class StorageService {

    private final FilePermissionGateway permissionGateway;

    public StorageService(FilePermissionGateway permissionGateway) {
        this.permissionGateway = permissionGateway;
    }

    /** 危险中间节点：原样透传用户指定的权限模式。 */
    public String store(String name, String content, String mode) {
        // 语义等价：Files.write(path, content.getBytes())
        // [CHECKPOINT id=JSEF-BIZ5-732-002 cwe=732 level=L5 source=attacker-controlled mode sink=FilePermissionGateway.apply expect=VULN trace=benchmark/cases/vuln/bizlogic5/FileUploadController.java:34,benchmark/cases/vuln/bizlogic5/FilePermissionGateway.java:16]
        return permissionGateway.apply(name, mode); // 用户可指定 0777
    }
}
