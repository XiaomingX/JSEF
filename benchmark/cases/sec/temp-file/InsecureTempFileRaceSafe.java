package com.jsef.benchmark.sec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * JSEF-Benchmark — 不安全临时文件（TOCTOU）安全对照（CWE-377，SAFE）
 *
 * 安全做法：原子创建并一次性设置权限，无竞争窗口。
 *
 * 修复要点（对照 InsecureTempFileRace.java）：createTempFile + 属性原子化。
 */
public class InsecureTempFileRaceSafe {

    public void store(String data) throws IOException {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        // [CHECKPOINT id=JSEF-QL-004S cwe=377 level=L2 source=data sink=Files.createTempFile (atomic 0600) expect=SAFE]
        Path tmp = Files.createTempFile("report-", ".tmp",
                PosixFilePermissions.asFileAttribute(perms));
        Files.write(tmp, data.getBytes());
    }

    public static void main(String[] args) throws IOException {
        new InsecureTempFileRaceSafe().store("localhost-demo-data");
    }
}
