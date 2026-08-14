// [VULN]
package com.jsef.benchmark.vuln;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * JSEF-Benchmark — Zip Slip 路径穿越解压 (CWE-22，难度 L2)
 *
 * 危险入口：解压时直接用 entry.getName() 拼接目标路径，未校验 ".."，
 * 攻击者在 zip 中放置 ../../etc/cron.d/payload 可写到目标目录之外。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实恶意 zip 内容。
 */
public class ZipSlip {

    /**
     * 危险：entry.getName() 直接拼路径，无 "../" 校验，可路径穿越写目录外。
     */
    static void unzip(InputStream zip, String destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(zip);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // [CHECKPOINT id=JSEF-ZIPSLIP-001 cwe=22 level=L2 source=entry.getName() sink=FileOutputStream expect=VULN]
            File out = new File(destDir, entry.getName()); // 未校验 entry name，可穿越
            FileOutputStream fos = new FileOutputStream(out);
            byte[] buf = new byte[4096];
            int n;
            while ((n = zis.read(buf)) > 0) fos.write(buf, 0, n);
            fos.close();
        }
    }
}
