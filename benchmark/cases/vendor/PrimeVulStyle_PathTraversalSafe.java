package com.jsef.benchmark.vendor;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import jakarta.servlet.http.HttpServletRequest;

/**
 * JSEF-Benchmark B6 — PrimeVul / CVEfixes 风格路径穿越（CWE-22）之 SAFE 修复版
 *
 * 抽象自 PrimeVul https://arxiv.org/abs/2403.18624 与 CVEfixes
 * https://github.com/secureIT-project/CVEfixes 。真实 CVE 修复对照常采用
 * base.resolve(name).normalize() 并校验结果仍位于 base 之内。
 *
 * 本文件为 {@link PrimeVulStyle_PathTraversal} 的 SAFE 配对：用 Paths.get(base).resolve(name)
 * .normalize() 防穿越，并校验最终路径不逃出 BASE_DIR（混淆样本，不应报）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class PrimeVulStyle_PathTraversalSafe {

    private static final String BASE_DIR = "/var/jsef/uploads";

    /**
     * SAFE：规范化后校验路径落在 BASE_DIR 内，阻断 ../ 穿越。
     */
    public void readSafe(HttpServletRequest request) throws IOException {
        String fileName = request.getParameter("file");
        // [CHECKPOINT id=JSEF-VEND-PT-001S cwe=22 level=L2 source=request.getParameter("file") sink=Files.newInputStream expect=SAFE]
        Path base = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path resolved = base.resolve(fileName).normalize();
        if (!resolved.startsWith(base)) {
            throw new SecurityException("path traversal blocked: " + fileName);
        }
        java.io.InputStream fis = java.nio.file.Files.newInputStream(resolved);
        fis.close();
    }
}
