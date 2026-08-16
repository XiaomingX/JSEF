/*
 * JSEF Benchmark 样本 — 弱哈希 MD5/SHA1 口令 (CWE-328, L2)
 * 用 MD5 哈希口令（无盐）。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import java.security.MessageDigest;

public class WeakHashMd5 {

    static byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // 弱哈希
        // [CHECKPOINT id=JSEF-EXT-012 cwe=328 level=L2 source=password sink=MessageDigest(MD5) digest expect=VULN]
        return md.digest(password.getBytes()); // 无盐，易撞库
    }
}
