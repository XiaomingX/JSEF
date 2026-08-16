/*
 * JSEF Benchmark 样本 — IDOR 按路径查文件越权 (CWE-639, L2)
 * 用户指定文件路径读取，未校验归属。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import java.nio.file.Files;
import java.nio.file.Paths;

public class IdorByPath {

    // source：@RequestParam filePath
    static String readFile(String filePath, String owner) throws Exception {
        // [CHECKPOINT id=JSEF-EXT-014 cwe=639 level=L2 source=@RequestParam filePath sink=Files.readAllBytes without ownership check expect=VULN]
        return new String(Files.readAllBytes(Paths.get(filePath))); // 可读取他人文件
    }
}
