package com.freedom.securitysamples.api.commandInjection;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;

@RestController
@RequestMapping("/api")
public class CommandInjectionController {

    @GetMapping("/command/bad01")
    public String executeCommand(@RequestParam String command) {
        StringBuilder output = new StringBuilder();

        try {
            // 不安全的命令执行，直接使用用户输入
            Process process = Runtime.getRuntime().exec(command);

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

    // 示例1：使用字符串拼接构建命令
    @GetMapping("/command/bad02")
    public String executeCommandWithArgs(@RequestParam String fileName) {
        StringBuilder output = new StringBuilder();
        try {
            // 不安全：直接拼接用户输入到命令字符串中
            String command = "cat " + fileName;
            Process process = Runtime.getRuntime().exec(command);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            return output.toString();
        } catch (Exception e) {
            return "命令执行错误: " + e.getMessage();
        }
    }

    // 示例2：使用数组但未进行适当过滤
    @GetMapping("/command/bad03")
    public String executeCommandArray(@RequestParam String command, @RequestParam String arg) {
        StringBuilder output = new StringBuilder();
        try {
            // 不安全：虽然使用数组，但未对参数进行适当验证
            String[] cmdArray = {command, arg};
            Process process = Runtime.getRuntime().exec(cmdArray);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            return output.toString();
        } catch (Exception e) {
            return "命令执行错误: " + e.getMessage();
        }
    }

    // 示例4：使用ProcessBuilder但配置不当
    @GetMapping("/command/bad04")
    public String executeWithProcessBuilder(@RequestParam String command) {
        StringBuilder output = new StringBuilder();
        try {
            // 不安全：ProcessBuilder配置不当，仍然可能被注入
            ProcessBuilder processBuilder = new ProcessBuilder(command.split(" "));
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            return output.toString();
        } catch (Exception e) {
            return "命令执行错误: " + e.getMessage();
        }
    }
}