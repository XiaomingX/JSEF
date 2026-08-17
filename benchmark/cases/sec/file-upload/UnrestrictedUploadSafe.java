package com.jsef.benchmark.sec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.UUID;

/*
 * JSEF-Benchmark L2 — 文件上传修复
 *
 * 修复：扩展名 + MIME 双重白名单，随机文件名（UUID 避免被预测/双写），
 * 文件落于隔离目录。即使攻击者提供 .phphpp 也会被白名单拒绝。
 *
 * CWE-434 (Unrestricted Upload of File with Dangerous Type)。
 */
public class UnrestrictedUploadSafe {

    static final String UPLOAD_DIR = "/tmp/jsef-uploads";
    static final Set<String> ALLOWED_EXT = Set.of(".jpg", ".jpeg", ".png");
    static final Set<String> ALLOWED_MIME = Set.of("image/jpeg", "image/png");

    /**
     * 安全路径：白名单 + 随机文件名 + 隔离目录。
     */
    public void handleUpload(String filename, String contentType, byte[] bytes) throws IOException {
        String lower = filename.toLowerCase();
        int dot = lower.lastIndexOf('.');
        String ext = (dot >= 0) ? lower.substring(dot) : "";
        if (!ALLOWED_EXT.contains(ext) || !ALLOWED_MIME.contains(contentType)) {
            throw new IllegalArgumentException("rejected");
        }
        String stored = UUID.randomUUID() + ext; // 随机名：杜绝双写/预测
        // [CHECKPOINT id=JSEF-NV101S cwe=434 level=L2 source=filename sink=Files.write (extension+mime whitelist + UUID + isolated dir) expect=SAFE]
        Files.write(Paths.get(UPLOAD_DIR, stored), bytes); // 仅白名单类型、随机名、隔离目录
    }

    public static void main(String[] args) throws Exception {
        Path p = Paths.get(UPLOAD_DIR);
        Files.createDirectories(p);
        new UnrestrictedUploadSafe().handleUpload("photo.jpg", "image/jpeg", "data".getBytes());
    }
}
