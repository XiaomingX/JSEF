/*
 * JSEF Benchmark 样本 — IDOR 安全对照 (CWE-639, L2/L3)
 * 每次访问前校验资源归属当前用户。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.sec;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class IdorSafe {

    interface Repo { String findById(long id); boolean owns(long id, long user); }

    static String getProfile(Repo repo, long userId, long currentUser) {
        if (!repo.owns(userId, currentUser)) throw new SecurityException("forbidden");
        // [CHECKPOINT id=JSEF-EXT-013S cwe=639 level=L2 source=@RequestParam userId sink=ownership check before repo.findById expect=SAFE]
        return repo.findById(userId);
    }

    static String readFile(String filePath, String owner) throws Exception {
        if (!filePath.startsWith("/data/" + owner + "/")) throw new SecurityException("forbidden");
        // [CHECKPOINT id=JSEF-EXT-014S cwe=639 level=L2 source=@RequestParam filePath sink=path ownership check before read expect=SAFE]
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }

    static List<String> export(Repo repo, long from, long to, long currentUser) {
        List<String> out = new ArrayList<>();
        for (long id = from; id <= to; id++) {
            if (!repo.owns(id, currentUser)) continue; // 逐条校验
            // [CHECKPOINT id=JSEF-EXT-015S cwe=639 level=L3 source=@RequestParam from/to sink=ownership check per item before export expect=SAFE]
            out.add(repo.findById(id));
        }
        return out;
    }
}
