package com.jsef.benchmark.vuln;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/*
 * JSEF-Benchmark L3 — 双重 URL 解码绕过
 *
 * 难度：L3（跨节点/路径语义）。防护在校验阶段对 userPath 做一次 URLDecoder.decode，
 * 过滤 ".." 后认为安全；但下游（或框架二次解码）又对校验后的字符串再解码一次，
 * 使得 "%252e%252e"（一次解码 "%2e%2e"，二次解码 ".."）在被写入时还原为 ".."。
 * 校验与最终使用之间存在“解码不一致”窗口，导致越界写入。
 *
 * CWE-22 (Path Traversal)。安全底线：仅 localhost 演示语义。
 *
 * 修复要点（对照 DoubleDecodeTraversalSafe.java）：先一次性 canonicalize 到最终形态，
 * 再统一校验，避免多次解码造成不一致。
 */
public class DoubleDecodeTraversalVuln {

    private static final String BASE_DIR = "/var/www/uploads";

    /**
     * 一次解码后校验白名单，下游二次解码后写入。
     *
     * @param userPath 用户可控、可能经编码的路径
     */
    public void write(String userPath) throws Exception {
        // 校验阶段：仅解码一次，过滤 ".."
        String decoded = URLDecoder.decode(userPath, StandardCharsets.UTF_8);   // 第一次解码
        if (decoded.contains("..")) {
            throw new SecurityException("path traversal blocked");
        }
        // 下游/框架：再次解码（不一致窗口）
        String finalPath = URLDecoder.decode(decoded, StandardCharsets.UTF_8);  // 第二次解码，%252e%252e -> ..
        byte[] data = "demo".getBytes();
        // [CHECKPOINT id=JSEF-NV203 cwe=22 level=L3 source=userPath sink=Files.write (after second decode) expect=VULN trace=benchmark/cases/vuln/double-decode/DoubleDecodeTraversalVuln.java:38,benchmark/cases/vuln/double-decode/DoubleDecodeTraversalVuln.java:44]
        Files.write(Paths.get(BASE_DIR, finalPath), data);                       // 二次解码还原 "../" 越界
    }

    public static void main(String[] args) throws Exception {
        new DoubleDecodeTraversalVuln().write("%252e%252e%252f%252e%252e%252fetc%252fpasswd");
    }
}
