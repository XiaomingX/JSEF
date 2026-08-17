package com.jsef.benchmark.vuln;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/*
 * JSEF-Benchmark L2 — 无限制文件上传（扩展名黑名单绕过）
 *
 * 难度：L2（多跳 + 防护语义缺陷）。服务端使用扩展名黑名单 endsWith(".jpg")
 * 校验，但攻击者可利用双写 ".phphpp"（结尾为 .hpp，黑名单不命中，落地后
 * 服务器按 .php 解析）或伪造 Content-Type 头绕过校验，将 webshell 落盘。
 *
 * CWE-434 (Unrestricted Upload of File with Dangerous Type)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 UnrestrictedUploadSafe.java）：扩展名 + MIME 白名单，
 * 随机文件名（UUID），隔离上传目录。
 */
public class UnrestrictedUploadVuln {

    static final String UPLOAD_DIR = "/tmp/jsef-uploads";

    /**
     * 危险路径：黑名单可被双写后缀 / 伪造 Content-Type 绕过。
     *
     * @param filename     用户可控文件名（可能为 shell.phphpp）
     * @param contentType  用户可控 Content-Type（可伪造为 image/png）
     * @param bytes        文件内容
     */
    public void handleUpload(String filename, String contentType, byte[] bytes) throws IOException {
        // 黑名单校验：仅检查结尾，.phphpp 不命中 .php；Content-Type 可伪造
        boolean ok = filename.endsWith(".jpg") || filename.endsWith(".png")
                || contentType.equals("image/jpeg") || contentType.equals("image/png");
        if (!ok) {
            throw new IllegalArgumentException("rejected");
        }
        // [CHECKPOINT id=JSEF-NV101 cwe=434 level=L2 source=filename (双写 .phphpp / 伪造 Content-Type) sink=Files.write (extension blacklist bypass) expect=VULN]
        Files.write(Paths.get(UPLOAD_DIR, filename), bytes); // 黑名单绕过：恶意 .phphpp 落盘
    }

    public static void main(String[] args) throws Exception {
        new UnrestrictedUploadVuln().handleUpload("shell.phphpp", "image/png", "<?php phpinfo();".getBytes());
    }
}
