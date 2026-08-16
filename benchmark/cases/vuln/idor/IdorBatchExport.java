/*
 * JSEF Benchmark 样本 — IDOR 批量导出越权 (CWE-639, L3)
 * 跨方法：导出时遍历 id 区间，未逐个校验归属。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import java.util.ArrayList;
import java.util.List;

public class IdorBatchExport {

    interface Repo { String findById(long id); }

    static List<String> export(Repo repo, long from, long to, long currentUser) {
        List<String> out = new ArrayList<>();
        for (long id = from; id <= to; id++) { // 跨方法遍历
            // [CHECKPOINT id=JSEF-EXT-015 cwe=639 level=L3 source=@RequestParam from/to sink=repo.findById in loop without ownership check expect=VULN]
            out.add(repo.findById(id)); // 批量越权导出
        }
        return out;
    }
}
