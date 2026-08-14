// [SAFE]
// 安全对照：硬编码凭证（修复版）
// 修复原则：敏感凭证从环境变量/配置中心读取，禁止硬编码；密码以哈希存储比对。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * 安全示例：数据库凭证从环境变量读取，避免硬编码。
 */
@RestController
@RequestMapping("/benchmark/sec/hardcoded-credentials")
public class HardcodedCredentialsSafe {

    /**
     * 安全示例：凭证来源于环境变量，而非代码字面量。
     */
    @GetMapping("/safe/db-connection")
    public String safeDbConnection() {
        try {
            String dbUrl = System.getenv("APP_DB_URL");
            String dbUsername = System.getenv("APP_DB_USER");
            String dbPassword = System.getenv("APP_DB_PASSWORD");
            if (dbUrl == null || dbUsername == null || dbPassword == null) {
                return "{\"msg\":\"凭证未配置\"}";
            }
            // 安全实践：凭证来自环境变量，代码中无硬编码字符串
            // [CHECKPOINT id=JSEF-HARDCODED-001S cwe=798 level=L1 source=env var (not hardcoded) sink=DriverManager.getConnection (secrets externalized) expect=SAFE]
            Connection conn = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
            return "{\"msg\":\"数据库已连接（凭证来自外部配置）\"}";
        } catch (Exception e) {
            return "{\"msg\":\"数据库连接失败\"}";
        }
    }
}
