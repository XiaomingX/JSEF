package com.jsef.benchmark.vuln;

import java.io.FileInputStream;
import java.io.IOException;

/**
 * JSEF-Benchmark L0 — 基线（路径遍历，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-22 Path Traversal。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0PathDirect {

    /**
     * 单跳：不可信入参直接作为文件路径打开（sink）。
     *
     * @param userInput 不可信输入（类比 request.getParameter("file")）
     */
    public void run(String userInput) throws IOException {
        // [CHECKPOINT id=JSEF-L0-PT-001 cwe=22 level=L0 source=userInput sink=new FileInputStream expect=VULN]
        FileInputStream fis = new FileInputStream(userInput);
    }

    public static void main(String[] args) throws IOException {
        new L0PathDirect().run("./localhost-demo.txt");
    }
}
