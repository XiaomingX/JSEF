package com.jsef.benchmark.sec;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/*
 * JSEF-Benchmark L1 — 文件上传大小限制修复 (CWE-400) expect=SAFE
 *
 * sec 侧：边读边累加已写入字节数，超过 LIMIT 立即抛异常，阻断超大文件。
 *
 * 安全底线：按实现判定为安全。
 */
public class UploadNoSizeLimitSafe {

    static final long LIMIT = 10 * 1024 * 1024; // 10 MB

    // [CHECKPOINT id=JSEF-NV403S cwe=400 level=L1 source=uploadStream sink=Files.copy (size-limited) expect=SAFE]
    public void upload(InputStream in) throws Exception {
        try (OutputStream out = Files.newOutputStream(Paths.get("/tmp/upload.bin"))) {
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > LIMIT) {
                    throw new IllegalStateException("upload exceeds size limit");
                }
                out.write(buf, 0, n);
            }
        }
    }
}
