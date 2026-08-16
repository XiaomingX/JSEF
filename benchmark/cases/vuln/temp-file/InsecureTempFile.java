package com.jsef.benchmark.vuln;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * JSEF-Benchmark — 不安全临时文件（CWE-377，L1 单跳）
 *
 * File.createTempFile 生成的文件名可预测（基于固定前缀 + 随机但可枚举的
 * 序号），且默认权限宽松。攻击者可在临时文件创建前抢占同名路径（符号链接
 * 攻击）或在写入前读取，导致敏感数据泄露或被篡改。
 *
 * CodeQL 对应查询：java/insecure-temporary-file / 不安全创建临时文件套件。
 *
 * 安全底线：仅 localhost 教学演示，不提供符号链接攻击利用脚本。
 *
 * 修复要点（对照 InsecureTempFileSafe.java）：使用
 * Files.createTempFile(Path, ...)，并通过 PosixFilePermissions 限制 0600
 * 权限，且避免固定可预测前缀。
 */
public class InsecureTempFile {

    /**
     * 单跳：用可预测临时文件名写入敏感数据。
     *
     * @param secret 敏感内容（类比下载的令牌/密钥）
     */
    public void writeSecret(String secret) throws IOException {
        // [CHECKPOINT id=JSEF-QL-003 cwe=377 level=L1 source=secret sink=File.createTempFile expect=VULN]
        File tmp = File.createTempFile("app-cache", ".tmp");
        try (FileWriter w = new FileWriter(tmp)) {
            w.write(secret);
        }
    }

    public static void main(String[] args) throws IOException {
        new InsecureTempFile().writeSecret("localhost-demo-secret");
    }
}
