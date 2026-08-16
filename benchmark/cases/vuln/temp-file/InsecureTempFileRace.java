package com.jsef.benchmark.vuln;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * JSEF-Benchmark — 不安全临时文件（TOCTOU 竞争，CWE-377，L2 多跳）
 *
 * 先创建临时文件，再单独设置权限（两步操作之间存在时间窗）。攻击者可利用
 * TOCTOU 在权限收紧前读取/替换文件，或在创建与写入之间注入符号链接。
 *
 * CodeQL 对应查询：java/insecure-temporary-file。
 *
 * 安全底线：仅 localhost 教学演示。
 *
 * 修复要点（对照 InsecureTempFileRaceSafe.java）：原子方式创建并设置权限，
 * 避免 createTempFile 与 setReadable/setWritable 分离。
 */
public class InsecureTempFileRace {

    /**
     * 多跳：createTempFile -> setReadable 两步（竞争窗口）。
     *
     * @param data 待写内容
     */
    public void store(String data) throws IOException {
        File tmp = File.createTempFile("report", ".tmp");
        tmp.setReadable(true, false); // 放宽权限，引入 TOCTOU 窗口
        tmp.setWritable(true, false);
        // [CHECKPOINT id=JSEF-QL-004 cwe=377 level=L2 source=data sink=File.createTempFile+setReadable expect=VULN]
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(data.getBytes());
        }
    }

    public static void main(String[] args) throws IOException {
        new InsecureTempFileRace().store("localhost-demo-data");
    }
}
