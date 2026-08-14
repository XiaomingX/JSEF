// [SAFE]
package com.jsef.benchmark.sec;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * JSEF-Benchmark — Zip Slip 安全对照 (CWE-22，难度 L2)
 *
 * 修复：校验 entry name 不以 "../" 开头，且规范化后必须落在目标目录内，
 * 否则跳过该条目。
 */
public class ZipSlipSafe {

    /**
     * 安全：校验 entry name，阻止路径穿越。
     */
    static void unzip(InputStream zip, String destDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(zip);
        ZipEntry entry;
        File dest = new File(destDir).getCanonicalFile();
        while ((entry = zis.getNextEntry()) != null) {
            File out = new File(dest, entry.getName()).getCanonicalFile();
            // [CHECKPOINT id=JSEF-ZIPSLIP-001S cwe=22 level=L2 source=entry.getName() sink=canonical-path check expect=SAFE]
            if (!out.toPath().startsWith(dest.toPath())) {
                continue; // 路径穿越，跳过
            }
            FileOutputStream fos = new FileOutputStream(out);
            byte[] buf = new byte[4096];
            int n;
            while ((n = zis.read(buf)) > 0) fos.write(buf, 0, n);
            fos.close();
        }
    }
}
