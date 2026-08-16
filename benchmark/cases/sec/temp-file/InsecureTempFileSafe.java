package com.jsef.benchmark.sec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * JSEF-Benchmark — 不安全临时文件安全对照（CWE-377，SAFE）
 *
 * 安全做法：Files.createTempFile 创建于安全目录，并显式设置 0600 权限，
 * 文件名由 JDK 安全随机生成，不可预测。
 *
 * 修复要点（对照 InsecureTempFile.java）：Files.createTempFile + 严格权限。
 */
public class InsecureTempFileSafe {

    public void writeSecret(String secret) throws IOException {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        // [CHECKPOINT id=JSEF-QL-003S cwe=377 level=L1 source=secret sink=Files.createTempFile (0600) expect=SAFE]
        Path tmp = Files.createTempFile("app-", ".tmp",
                PosixFilePermissions.asFileAttribute(perms));
        Files.write(tmp, secret.getBytes());
    }

    public static void main(String[] args) throws IOException {
        new InsecureTempFileSafe().writeSecret("localhost-demo-secret");
    }
}
