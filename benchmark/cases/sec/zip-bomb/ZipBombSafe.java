package com.jsef.benchmark.sec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/*
 * JSEF-Benchmark L2 — ZIP 炸弹修复 (CWE-409) expect=SAFE
 *
 * sec 侧：校验单 entry 声明大小 <= MAX，并累加已解压字节不超过总量上限，
 * 任一超限立即抛异常，阻断炸弹。
 *
 * 安全底线：按实现判定为安全。
 */
public class ZipBombSafe {

    static final long MAX_ENTRY = 64 * 1024 * 1024;   // 单 entry 64MB
    static final long MAX_TOTAL = 256 * 1024 * 1024;  // 累计 256MB

    // [CHECKPOINT id=JSEF-NV404S cwe=409 level=L2 source=zipBytes sink=ZipInputStream entries (size-checked) expect=SAFE]
    public void extract(byte[] zipBytes) throws Exception {
        InputStream is = new ByteArrayInputStream(zipBytes);
        try (ZipInputStream zis = new ZipInputStream(is)) {
            ZipEntry e;
            long total = 0;
            while ((e = zis.getNextEntry()) != null) {
                long size = e.getSize();
                if (size > MAX_ENTRY) {
                    throw new IllegalStateException("zip entry too large");
                }
                byte[] buf = new byte[8192];
                int n;
                while ((n = zis.read(buf)) > 0) {
                    total += n;
                    if (total > MAX_TOTAL) {
                        throw new IllegalStateException("zip total too large");
                    }
                }
            }
        }
    }
}
