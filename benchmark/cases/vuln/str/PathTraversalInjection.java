/*
 * JSEF Benchmark — FP 混淆型安全样本的对照 vuln（CWE-22, 难度 L3）
 *
 * 对照样本：用户输入未校验直接拼入路径，可路径遍历（"../../etc/passwd"）。
 * 与 WhitelistPathSafe 的白名单 Gate 形成 vuln/safe 对。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.io.File;

public class PathTraversalInjection {

    /**
     * 危险入口：userPath 未经校验直接拼入路径，可遍历。
     * @param userPath 不可信用户输入
     */
    static File unsafe(String baseDir, String userPath) {
        String path = baseDir + "/" + userPath;
        // [CHECKPOINT id=JSEF-FP-005V cwe=22 level=L3 source=userPath sink=new File(concat) expect=VULN]
        return new File(path);
    }
}
