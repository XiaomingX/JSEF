package com.jsef.benchmark.sec;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * JSEF-Benchmark L0 — L0PathDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：将不可信文件名限制在固定基目录内，规范化后校验前缀，拒绝越界路径。
 * 用于计算 TN（正确不报）/ FP（误报）。
 *
 * CWE-22 Path Traversal。
 */
public class L0PathDirectSafe {

    private static final String BASE_DIR = "/var/local/bench/data";

    /**
     * 路径校验：规范化后限制于 BASE_DIR 内。
     *
     * @param userInput 不可信输入
     */
    public void run(String userInput) throws IOException {
        String resolved = Paths.get(BASE_DIR, userInput).normalize().toString();
        if (!resolved.startsWith(BASE_DIR)) {
            throw new SecurityException("path traversal blocked: " + userInput);
        }
        // [CHECKPOINT id=JSEF-L0-PT-001S cwe=22 level=L0 source=userInput sink=new FileInputStream expect=SAFE]
        FileInputStream fis = new FileInputStream(resolved);
    }

    public static void main(String[] args) throws IOException {
        new L0PathDirectSafe().run("localhost-demo.txt");
    }
}
