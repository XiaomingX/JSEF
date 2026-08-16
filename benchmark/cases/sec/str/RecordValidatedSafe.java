/*
 * JSEF Benchmark — FP 混淆型安全样本（CWE-79, 难度 L4）
 *
 * 样本 5：Records 不可变语义 safe — 字段在构造时即经校验，record 不可变，
 *   看似可被污染实则构造期已 Gate，下游使用无注入风险。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

public class RecordValidatedSafe {

    /**
     * 不可变 record：name 在规范构造器内校验，仅允许字母数字。
     * @param rawName 不可信用户输入
     */
    public record UserName(String name) {
        public UserName {
            if (name == null || !name.matches("[A-Za-z0-9]+")) {
                throw new IllegalArgumentException("invalid name");
            }
        }
    }

    /**
     * 安全入口：record 实例字段构造时即受限，下游直接用于输出无注入。
     */
    static String safe(String rawName) {
        UserName u = new UserName(rawName);
        String out = "<span>" + u.name() + "</span>";
        // [CHECKPOINT id=JSEF-FP-006 cwe=79 level=L4 source=record field (validated at construction) sink=response output expect=SAFE]
        return out;
    }
}
