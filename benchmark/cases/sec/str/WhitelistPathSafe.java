/*
 * JSEF Benchmark — FP 混淆型安全样本（CWE-22, 难度 L3）
 *
 * 样本 4：白名单校验后 safe — 用户输入经 allowedPaths.contains() 白名单校验，
 *   仅当命中白名单才拼入路径，污点被白名单 Gate 阻断，无法遍历。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.io.File;
import java.util.List;

public class WhitelistPathSafe {

    private static final List<String> allowedPaths = List.of("report", "avatar", "log");

    /**
     * 安全入口：userPath 经白名单校验后才拼入 base 路径。
     * @param userPath 不可信用户输入（如 "../../etc/passwd" 会被拒绝）
     */
    static File safe(String baseDir, String userPath) {
        if (!allowedPaths.contains(userPath)) {
            throw new IllegalArgumentException("path not allowed");
        }
        String path = baseDir + "/" + userPath;
        // [CHECKPOINT id=JSEF-FP-005 cwe=22 level=L3 source=userPath sink=new File(whitelisted) expect=SAFE]
        return new File(path);
    }
}
