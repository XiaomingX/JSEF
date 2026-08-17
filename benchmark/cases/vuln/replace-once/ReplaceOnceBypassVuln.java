package com.jsef.benchmark.vuln;

import java.nio.file.Files;
import java.nio.file.Paths;

/*
 * JSEF-Benchmark L2 — 单次 replace 清洗绕过
 *
 * 难度：L2（多跳但无断点）。防护用 userPath.replace("..", "") 单次删除 ".."，
 * 但 "...//" 经过一次替换会残留 "../"（替换不递归）："....//" -> "../"。
 * 攻击者可借此越出 baseDir。
 *
 * CWE-22 (Path Traversal)。安全底线：仅 localhost 演示语义。
 *
 * 修复要点（对照 ReplaceOnceBypassSafe.java）：用正则白名单限定字符集，
 * 并保证规范化后仍位于 BASE_DIR 内。
 */
public class ReplaceOnceBypassVuln {

    private static final String BASE_DIR = "/var/www/uploads";

    /**
     * 单次 replace("..","") 清洗后拼接写入。
     *
     * @param userPath 用户可控路径
     */
    public void write(String userPath) throws Exception {
        String safe = userPath.replace("..", "");          // 单次替换，可被 ....// 绕过
        byte[] data = "demo".getBytes();
        // [CHECKPOINT id=JSEF-NV202 cwe=22 level=L2 source=userPath sink=Files.write (after single replace("..","")) expect=VULN]
        Files.write(Paths.get(BASE_DIR, safe), data);      // ....// -> ../ 越界
    }

    public static void main(String[] args) throws Exception {
        new ReplaceOnceBypassVuln().write("....//....//etc/passwd");
    }
}
