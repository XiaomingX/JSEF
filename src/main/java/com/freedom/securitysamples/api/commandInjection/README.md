```java
package com.freedom.securitysamples.api.commandInjection;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/api")
public class CommandInjectionController {

    @GetMapping("/command/bad01")
    public String executeCommand(@RequestParam String command) {
        StringBuilder output = new StringBuilder();
        
        try {
            // 不安全的命令执行，直接使用用户输入
            Process process = Runtime.getRuntime().exec(command);
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            process.waitFor();
            reader.close();
            
            return output.toString();
            
        } catch (Exception e) {
            return "命令执行错误: " + e.getMessage();
        }
    }
}
```

这段代码存在以下安全问题：

1. **命令注入漏洞**：
    - 直接使用未经过滤的用户输入(`command`)执行系统命令
    - 没有对输入进行任何验证或清理
    - 允许执行任意系统命令

2. **攻击示例**：
   攻击者可以输入如下参数：
   ```
   cmd.exe /c dir & del important.txt  // Windows
   ls -la; rm -rf *  // Linux
   ```

3. **安全建议**：
    - 避免直接使用Runtime.exec()执行系统命令
    - 对用户输入进行严格的验证和过滤
    - 使用白名单限制可执行的命令
    - 使用参数化命令替代字符串拼接

请注意，这段代码仅用于演示命令注入漏洞，不要在生产环境中使用。在实际应用中应该采取适当的安全措施来防止命令注入攻击。