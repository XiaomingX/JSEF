// [VULN]（安全对照样本，expect=SAFE）
package com.jsef.benchmark.sec.msprecon;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark — 多步规划 P3 安全对照 (难度 L4, CWE-89, expect=SAFE)
 *
 * 修复思路（对照 vuln 版本 ReconChainSql_*）：
 *   排序字段经白名单映射，不可信 sortField 无法直接拼入查询方法名/SQL。
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
@RestController
public class ReconChainSql_Safe {

    private static final java.util.Set<String> ALLOWED = java.util.Set.of("id", "name", "createdAt");

    @GetMapping("/benchmark/recon/sql/safe")
    public Object list(@RequestParam String sortField) {
        // [CHECKPOINT id=JSEF-MSP-003S cwe=89 level=L4 source=@RequestParam sortField sink=whitelist reject expect=SAFE]
        if (!ALLOWED.contains(sortField)) {
            return "invalid sort field"; // 不可信字段被拒，无法到达查询
        }
        String methodName = "findBy" + sortField; // 白名单内字段才可拼入
        System.out.println("[abstract sql] select * from t order by " + methodName);
        return "rows";
    }
}
