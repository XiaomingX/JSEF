// [VULN] (安全对照：此处应为 SAFE)
package com.jsef.benchmark.sec.bizlogic5;

/**
 * 文件权限网关（安全版）：权限由服务层安全值决定，用户不可控。
 */
public class FilePermissionGatewaySafe {

    public String apply(String name, String safeMode) {
        // 语义等价：Files.setPosixFilePermissions(path, fromMode(safeMode))
        System.out.println("[fs-chmod][safe] chmod " + safeMode + " " + name);
        return "stored:" + name + ":" + safeMode;
    }
}
