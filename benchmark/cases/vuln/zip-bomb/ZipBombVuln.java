package com.jsef.benchmark.vuln;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/*
 * JSEF-Benchmark L2 — ZIP 炸弹：不解压大小/压缩比校验 (CWE-409)
 *
 * 难度：L2（多跳）。zipBytes 经 ZipInputStream 逐个 entry 读出，
 * 未校验 e.getSize() 与累计解压大小，构造高冗余炸弹耗尽内存/磁盘。
 *
 * 安全底线：仅 localhost 演示语义。
 * 修复要点（ZipBombSafe.java）：校验单 entry 大小与累计上限。
 */
public class ZipBombVuln {

    // [CHECKPOINT id=JSEF-NV404 cwe=409 level=L2 source=zipBytes sink=ZipInputStream entries (no ratio/size check) expect=VULN]
    public void extract(byte[] zipBytes) throws Exception {
        InputStream is = new ByteArrayInputStream(zipBytes);
        // 不校验 e.getSize() / 压缩比，直接解压
        try (ZipInputStream zis = new ZipInputStream(is)) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                byte[] buf = new byte[8192];
                while (zis.read(buf) > 0) { /* drain */ }
            }
        }
    }
}
