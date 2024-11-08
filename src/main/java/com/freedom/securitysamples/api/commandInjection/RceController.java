package com.freedom.securitysamples.api.commandInjection;

import cn.hutool.core.util.RuntimeUtil;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.util.Arrays;

@RestController
@RequestMapping("/api")
public class RceController {

    @GetMapping("/rce/bad01")
    public String executeCommand01(String command) throws IOException {
        java.lang.Runtime.getRuntime().exec(command);
        return "success";
    }

    @GetMapping("/rce/bad02")
    public String executeCommand02(String command) throws IOException {
        String commandResult = RuntimeUtil.execForStr(command);
        return commandResult;
    }

    @GetMapping("/rce/bad03")
    public String executeCommand03(String commandInput) throws IOException {
        String[] commandArray = new String[] {Arrays.toString(commandInput.split(" "))};
        new ProcessBuilder(commandArray).start();
        return "";
    }

    // 1. 使用shell=true的危险写法
    @GetMapping("/rce/bad04")
    public String executeCommand04(String command) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);
        Process process = processBuilder.start();
        return "executed";
    }

    // 2. 直接拼接命令字符串
    @GetMapping("/rce/bad05")
    public String executeCommand05(String userInput) throws IOException {
        String command = "ping " + userInput;
        Runtime.getRuntime().exec(command);
        return "ping executed";
    }

    // 3. 不当使用字符串数组
    @PostMapping("/rce/bad06")
    public String executeCommand06(@RequestBody String[] commands) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(commands);
        processBuilder.start();
        return "array command executed";
    }

    // 4. 使用未经过滤的环境变量
    @GetMapping("/rce/bad07")
    public String executeCommand07(String envName) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder("echo", "$" + envName);
        processBuilder.environment().put(envName, "INJECTED_VALUE");
        processBuilder.start();
        return "env command executed";
    }

    // 5. 不安全的文件操作结合命令执行
    @GetMapping("/rce/bad08")
    public String executeCommand08(String fileName) throws IOException {
        String command = "cat /tmp/" + fileName;
        return RuntimeUtil.execForStr(command);
    }
}