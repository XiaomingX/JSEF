// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

/**
 * 文件权限网关（危险 sink：设置文件权限）。
 *
 * 语义等价：Files.setPosixFilePermissions(path, fromMode(mode))。
 * 缺陷：mode 直接来自用户请求，可设为 0777（全局可写/可执行），
 *      导致敏感文件被任意用户篡改或执行（CWE-732）。
 */
public class FilePermissionGateway {

    /** 危险终点：按外部可控 mode 设置文件权限。 */
    public String apply(String name, String mode) {
        // 语义等价：Set<PosixFilePermission> perms = parseOctal(mode); Files.setPosixFilePermissions(path, perms)
        // [CHECKPOINT id=JSEF-BIZ5-732-003 cwe=732 level=L5 source=attacker-controlled mode sink=set file permission (e.g. 0777) expect=VULN trace=benchmark/cases/vuln/bizlogic5/FileUploadController.java:34,benchmark/cases/vuln/bizlogic5/StorageService.java:21]
        System.out.println("[fs-chmod] chmod " + mode + " " + name);
        return "stored:" + name + ":" + mode;
    }
}
