package com.freedom.securitysamples.api.sqlInjection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SqlInjectionController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 1. 不安全：直接字符串拼接
    @GetMapping("/user/search")
    public List<Map<String, Object>> searchUsers(@RequestParam String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // 2. 不安全：动态WHERE条件
    @GetMapping("/user/filter")
    public List<Map<String, Object>> filterUsers(@RequestParam String condition) {
        String sql = "SELECT * FROM users WHERE " + condition;
        return jdbcTemplate.queryForList(sql);
    }

    // 3. 不安全：多个参数拼接
    @GetMapping("/user/advanced-search")
    public List<Map<String, Object>> advancedSearch(
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String role) {
        String sql = "SELECT * FROM users WHERE username = '" + username +
                "' AND email = '" + email +
                "' AND role = '" + role + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // 4. 不安全：ORDER BY子句
    @GetMapping("/user/sort")
    public List<Map<String, Object>> sortUsers(@RequestParam String sortColumn) {
        String sql = "SELECT * FROM users ORDER BY " + sortColumn;
        return jdbcTemplate.queryForList(sql);
    }

    // 5. 不安全：LIKE查询
    @GetMapping("/user/search-like")
    public List<Map<String, Object>> searchUsersLike(@RequestParam String searchTerm) {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + searchTerm + "%'";
        return jdbcTemplate.queryForList(sql);
    }

    // 6. 不安全：IN子句
    @GetMapping("/user/search-in")
    public List<Map<String, Object>> searchUsersIn(@RequestParam String userIds) {
        String sql = "SELECT * FROM users WHERE id IN (" + userIds + ")";
        return jdbcTemplate.queryForList(sql);
    }

    // 7. 不安全：UPDATE语句
    @PostMapping("/user/update-status")
    public int updateUserStatus(
            @RequestParam String userId,
            @RequestParam String status) {
        String sql = "UPDATE users SET status = '" + status +
                "' WHERE id = " + userId;
        return jdbcTemplate.update(sql);
    }

    // 8. 不安全：DELETE语句
    @DeleteMapping("/user/delete")
    public int deleteUser(@RequestParam String condition) {
        String sql = "DELETE FROM users WHERE " + condition;
        return jdbcTemplate.update(sql);
    }

    // 9. 不安全：JOIN查询
    @GetMapping("/user/join-search")
    public List<Map<String, Object>> joinSearch(@RequestParam String deptName) {
        String sql = "SELECT u.* FROM users u " +
                "JOIN departments d ON u.dept_id = d.id " +
                "WHERE d.name = '" + deptName + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // 10. 不安全：GROUP BY查询
    @GetMapping("/user/group-stats")
    public List<Map<String, Object>> groupStats(@RequestParam String groupField) {
        String sql = "SELECT " + groupField + ", COUNT(*) as count " +
                "FROM users GROUP BY " + groupField;
        return jdbcTemplate.queryForList(sql);
    }

    // 安全的实现方式示例
    @GetMapping("/user/safe-search")
    public List<Map<String, Object>> safeSearch(@RequestParam String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        return jdbcTemplate.queryForList(sql, username);
    }

    // 安全的多参数查询示例
    @GetMapping("/user/safe-advanced-search")
    public List<Map<String, Object>> safeAdvancedSearch(
            @RequestParam String username,
            @RequestParam String email,
            @RequestParam String role) {
        String sql = "SELECT * FROM users WHERE username = ? AND email = ? AND role = ?";
        return jdbcTemplate.queryForList(sql, username, email, role);
    }
}