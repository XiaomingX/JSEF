```java
package com.freedom.securitysamples.api.sqlInjection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SqlInjectionController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 不安全的SQL查询示例 - 存在SQL注入漏洞
    @GetMapping("/user/search")
    public List<Map<String, Object>> searchUsers(@RequestParam String username) {
        // 直接拼接SQL语句，这是不安全的做法
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        
        // 执行不安全的SQL查询
        return jdbcTemplate.queryForList(sql);
    }

    // 另一个不安全的示例 - 使用动态SQL
    @GetMapping("/user/filter")
    public List<Map<String, Object>> filterUsers(@RequestParam String condition) {
        // 直接将用户输入拼接到SQL中，这是危险的
        String sql = "SELECT * FROM users WHERE " + condition;
        
        return jdbcTemplate.queryForList(sql);
    }
}
```

这个示例代码存在以下SQL注入漏洞：

1. 在 `searchUsers` 方法中：
- 直接将用户输入的 `username` 拼接到SQL语句中
- 攻击者可以输入类似 `' OR '1'='1` 这样的payload来绕过认证

2. 在 `filterUsers` 方法中：
- 完全接受用户输入作为WHERE子句的条件
- 攻击者可以注入任意SQL语句

攻击示例：
```
// 可能的攻击URL
http://localhost:8080/api/user/search?username=admin' OR '1'='1
http://localhost:8080/api/user/filter?condition=1=1 OR 1=1
```

要修复这些漏洞，应该：
1. 使用参数化查询
2. 使用PreparedStatement
3. 对输入进行严格验证和转义
4. 使用ORM框架的安全查询方法

安全的写法应该是：
```java
//@GetMapping("/user/search/safe")
//public List<Map<String, Object>> searchUsersSafely(@RequestParam String username) {
//    String sql = "SELECT * FROM users WHERE username = ?";
//    return jdbcTemplate.queryForList(sql, username);
//}
```
