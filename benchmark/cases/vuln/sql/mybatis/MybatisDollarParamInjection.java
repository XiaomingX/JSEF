/*
 * JSEF Benchmark — FP 混淆型安全样本的对照 vuln（CWE-89, 难度 L3）
 *
 * 对照样本：MyBatis @Select 内使用 ${userName} 字符串拼接，污点到达 SQL 文本。
 * 与 MybatisHashParamSafe 的 #{userName} 参数化形成 vuln/safe 对。
 * 安全底线：所有 Payload 仅 localhost 演示语义，不写真实利用脚本。
 */
package com.jsef.benchmark.vuln;

import java.util.List;
import java.util.Map;

public class MybatisDollarParamInjection {

    public interface UserMapper {
        List<Map<String, Object>> findBy(String name);
    }

    /**
     * 危险入口：@Select 内 userName 经 ${userName} 拼接，进入 SQL 文本可注入。
     * @param userName 不可信用户输入（如 "' OR '1'='1"）
     */
    static List<Map<String, Object>> unsafe(UserMapper mapper, String userName) {
        // 等价于 @Select("SELECT * FROM users WHERE name = '${userName}'")
        String sql = "SELECT * FROM users WHERE name = '" + userName + "'";
        // [CHECKPOINT id=JSEF-FP-003V cwe=89 level=L3 source=userName sink=@Select(${} concat) expect=VULN]
        return mapper.findBy(userName);
    }
}
