/*
 * JSEF Benchmark 样本 — IDOR 按 userId 越权查询 (CWE-639, L2)
 * 用请求中的 userId 直接查数据，未校验归属当前用户。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

public class IdorByUserId {

    interface Repo { String findById(long id); }

    // source：@RequestParam userId
    static String getProfile(Repo repo, long userId, long currentUser) {
        // [CHECKPOINT id=JSEF-EXT-013 cwe=639 level=L2 source=@RequestParam userId sink=repo.findById(userId) without ownership check expect=VULN]
        return repo.findById(userId); // 可查看他人资料
    }
}
