/*
 * JSEF Benchmark — FP 混淆型安全样本（CWE-89, 难度 L3）
 *
 * 样本 2：框架语义 safe — MyBatis @Select 使用 #{} 参数化（安全）
 *   污点看似到达 SQL 文本，但 #{} 由 MyBatis 框架按 JDBC 参数绑定处理，
 *   不会拼入 SQL 语句文本，无注入可能。对照危险写法为 ${} 拼接。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.sec;

import java.util.List;
import java.util.Map;

public class MybatisHashParamSafe {

    public interface UserMapper {
        List<Map<String, Object>> findBy(String name);
    }

    /**
     * 安全入口：@Select 内 userName 经 #{userName} 参数化，框架转 JDBC ? 绑定。
     * @param userName 不可信用户输入（如 "' OR '1'='1"）
     */
    static List<Map<String, Object>> safe(UserMapper mapper, String userName) {
        // 等价于 @Select("SELECT * FROM users WHERE name = #{userName}")
        String sql = "SELECT * FROM users WHERE name = #{userName}";
        // [CHECKPOINT id=JSEF-FP-003 cwe=89 level=L3 source=userName sink=@Select(#{} parameterized) expect=SAFE]
        return mapper.findBy(userName);
    }
}
