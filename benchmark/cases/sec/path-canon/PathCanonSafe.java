package com.jsef.benchmark.sec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * JSEF-Benchmark L3 — 路径规范化修复
 *
 * 修复：写入前先 toRealPath() 取得规范化路径，并校验其以 BASE_DIR 规范化前缀开头。
 * 即使输入含 ".."，规范化后也会被限制在 BASE_DIR 之内。
 *
 * CWE-22。SAFE 侧按实现判安全。
 */
public class PathCanonSafe {

    private static final String BASE_DIR = "/var/www/uploads";

    /**
     * 先规范化再校验前缀后写入。
     *
     * @param userPath 用户可控的相对路径
     */
    public void write(String userPath) throws Exception {
        Path baseDirNormalized = Paths.get(BASE_DIR).toRealPath();
        Path p = Paths.get(BASE_DIR).resolve(userPath).normalize();
        if (!p.toRealPath().startsWith(baseDirNormalized)) {
            throw new SecurityException("path traversal blocked");
        }
        byte[] data = "demo".getBytes();
        // [CHECKPOINT id=JSEF-NV201S cwe=22 level=L3 source=userPath sink=Files.write (after toRealPath + prefix check) expect=SAFE]
        Files.write(p, data);
    }

    public static void main(String[] args) throws Exception {
        new PathCanonSafe().write("../../etc/passwd");
    }
}
