package com.jsef.benchmark.sec;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * JSEF-Benchmark L3 — 双重 URL 解码修复
 *
 * 修复：先一次性把路径 canonicalize 到最终形态（此处直接以原始串做一次权威解码 +
 * normalize），再校验规范化结果不含 ".." 且位于 BASE_DIR 内。全链路只解码一次，
 * 杜绝校验/使用不一致的窗口。
 *
 * CWE-22。SAFE 侧按实现判安全。
 */
public class DoubleDecodeTraversalSafe {

    private static final String BASE_DIR = "/var/www/uploads";

    /**
     * 一次性解码并规范化后校验写入。
     *
     * @param userPath 用户可控、可能经编码的路径
     */
    public void write(String userPath) throws Exception {
        // 仅做一次权威解码，得到最终形态
        String canonical = URLDecoder.decode(userPath, StandardCharsets.UTF_8);
        Path p = Paths.get(BASE_DIR).resolve(canonical).normalize();
        if (canonical.contains("..") || !p.startsWith(Paths.get(BASE_DIR).normalize())) {
            throw new SecurityException("path traversal blocked");
        }
        byte[] data = "demo".getBytes();
        // [CHECKPOINT id=JSEF-NV203S cwe=22 level=L3 source=userPath sink=Files.write (after single decode + normalize) expect=SAFE]
        Files.write(p, data);
    }

    public static void main(String[] args) throws Exception {
        new DoubleDecodeTraversalSafe().write("%252e%252e%252f%252e%252e%252fetc%252fpasswd");
    }
}
