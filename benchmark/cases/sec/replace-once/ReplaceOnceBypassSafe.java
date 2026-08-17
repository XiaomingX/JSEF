package com.jsef.benchmark.sec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/*
 * JSEF-Benchmark L2 — 单次 replace 清洗修复
 *
 * 修复：用白名单正则 ^[a-zA-Z0-9_./-]+$ 校验，再规范化并校验前缀。
 * 既拒绝 ".." 这类非法序列，也约束字符范围，杜绝 ....// 变形。
 *
 * CWE-22。SAFE 侧按实现判安全。
 */
public class ReplaceOnceBypassSafe {

    private static final String BASE_DIR = "/var/www/uploads";
    private static final Pattern SAFE = Pattern.compile("^[a-zA-Z0-9_./-]+$");

    /**
     * 白名单正则校验后规范化写入。
     *
     * @param userPath 用户可控路径
     */
    public void write(String userPath) throws Exception {
        if (!SAFE.matcher(userPath).matches()) {
            throw new SecurityException("illegal path characters");
        }
        Path p = Paths.get(BASE_DIR).resolve(userPath).normalize();
        if (!p.startsWith(Paths.get(BASE_DIR).normalize())) {
            throw new SecurityException("path traversal blocked");
        }
        byte[] data = "demo".getBytes();
        // [CHECKPOINT id=JSEF-NV202S cwe=22 level=L2 source=userPath sink=Files.write (after whitelist + normalize) expect=SAFE]
        Files.write(p, data);
    }

    public static void main(String[] args) throws Exception {
        new ReplaceOnceBypassSafe().write("....//....//etc/passwd");
    }
}
