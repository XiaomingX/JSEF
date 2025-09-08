package com.freedom.securitysamples.api.commandInjection;

import cn.hutool.core.util.RuntimeUtil;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;
import java.util.Arrays;

/**
 * 命令注入（Command Injection）漏洞示例控制器
 * 说明：命令注入是指攻击者通过构造恶意输入，使应用程序执行非预期的系统命令
 * 这种漏洞通常出现在应用程序需要调用系统命令，且直接使用了未验证的用户输入时
 * 
 * 常见风险：
 * 1. 服务器被完全控制（执行任意命令、创建管理员账户等）
 * 2. 敏感数据泄露（读取密码文件、配置文件等）
 * 3. 数据被篡改或删除（删除文件、格式化磁盘等）
 * 4. 作为跳板攻击内网其他系统
 * 
 * 修复原则：
 * 1. 避免直接执行系统命令，优先使用编程语言内置功能
 * 2. 必须使用时，严格验证用户输入（白名单机制）
 * 3. 避免拼接命令字符串，使用参数数组传递参数
 * 4. 限制执行命令的用户权限，遵循最小权限原则
 * 5. 禁止使用shell解释器（如bash -c）执行命令
 */
@RestController
@RequestMapping("/security-example/command-injection")
public class RceController {

    /**
     * 不安全示例1：直接执行用户输入的完整命令
     * 漏洞点：将用户输入直接作为系统命令执行，无任何过滤
     * 风险：攻击者可输入任意系统命令（如rm -rf /、whoami等）
     * 示例攻击输入：ls -la; rm -rf /tmp/sensitive.txt
     * 攻击结果：执行了列表命令后，删除了敏感文件
     */
    @GetMapping("/unsafe/direct-execute")
    public String unsafeExecuteDirectCommand(@RequestParam String userInputCommand) throws IOException {
        // 危险实践：直接执行用户提供的完整命令
        Runtime.getRuntime().exec(userInputCommand);
        return "命令已执行（危险：未验证输入）";
    }

    /**
     * 不安全示例2：执行用户命令并返回结果
     * 漏洞点：执行用户输入的命令并返回输出，扩大了信息泄露风险
     * 风险：攻击者可通过命令结果获取系统信息，为进一步攻击做准备
     * 示例攻击输入：cat /etc/passwd
     * 攻击结果：获取系统用户列表信息
     */
    @GetMapping("/unsafe/execute-and-return")
    public String unsafeExecuteAndReturnResult(@RequestParam String userInputCommand) throws IOException {
        // 危险实践：执行用户命令并返回结果，泄露系统信息
        String commandResult = RuntimeUtil.execForStr(userInputCommand);
        return "命令执行结果：" + commandResult;
    }

    /**
     * 不安全示例3：错误处理命令参数数组
     * 漏洞点：错误地将用户输入分割后作为命令数组，实际仍为单字符串命令
     * 风险：本质上还是执行完整的用户输入命令，无法防止注入
     * 示例攻击输入：ls; pwd
     * 攻击结果：错误的数组处理方式导致多个命令被执行
     */
    @GetMapping("/unsafe/incorrect-array-handle")
    public String unsafeIncorrectArrayHandling(@RequestParam String commandInput) throws IOException {
        // 危险实践：错误的参数数组处理，未能真正分离命令和参数
        String[] commandArray = new String[] {Arrays.toString(commandInput.split(" "))};
        new ProcessBuilder(commandArray).start();
        return "命令数组已执行（危险：错误的参数处理）";
    }

    /**
     * 不安全示例4：使用shell解释器执行命令
     * 漏洞点：通过bash -c执行用户输入，允许命令拼接和管道操作
     * 风险：攻击者可使用分号(;)、管道(|)等符号注入多个命令
     * 示例攻击输入：ls -la; id
     * 攻击结果：同时执行了列表命令和查看用户身份命令
     */
    @GetMapping("/unsafe/use-shell-interpreter")
    public String unsafeUseShellInterpreter(@RequestParam String userInput) throws IOException {
        // 危险实践：使用bash -c执行命令，允许命令注入
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", userInput); // 使用shell解释器是高风险行为
        processBuilder.start();
        return "Shell命令已执行（危险：使用了shell解释器）";
    }

    /**
     * 不安全示例5：拼接命令字符串
     * 漏洞点：将用户输入直接拼接到预设命令中
     * 风险：攻击者可通过;、&等符号注入额外命令
     * 示例攻击输入：127.0.0.1; ls -la
     * 攻击结果：执行ping命令后，额外执行了列表命令
     */
    @GetMapping("/unsafe/command-concatenation")
    public String unsafeCommandConcatenation(@RequestParam String userInput) throws IOException {
        // 危险实践：直接拼接用户输入到命令中
        String command = "ping " + userInput; // 拼接导致注入风险
        Runtime.getRuntime().exec(command);
        return "Ping命令已执行（危险：命令字符串拼接）";
    }

    /**
     * 不安全示例6：直接使用用户提供的命令数组
     * 漏洞点：未验证用户提供的完整命令数组
     * 风险：攻击者可构造包含恶意命令和参数的数组
     * 示例攻击输入：["rm", "-rf", "/tmp/critical/*"]
     * 攻击结果：删除了关键目录下的所有文件
     */
    @PostMapping("/unsafe/raw-command-array")
    public String unsafeRawCommandArray(@RequestBody String[] userCommandArray) throws IOException {
        // 危险实践：直接使用用户提供的命令数组
        ProcessBuilder processBuilder = new ProcessBuilder(userCommandArray);
        processBuilder.start();
        return "命令数组已执行（危险：未验证数组内容）";
    }

    /**
     * 不安全示例7：使用未过滤的环境变量
     * 漏洞点：将用户输入作为环境变量名，可能导致变量注入
     * 风险：攻击者可通过特殊变量名影响命令执行环境
     * 示例攻击输入：PATH
     * 攻击结果：可能篡改命令查找路径，执行恶意程序
     */
    @GetMapping("/unsafe/unfiltered-env-variable")
    public String unsafeUnfilteredEnvVariable(@RequestParam String envVariableName) throws IOException {
        // 危险实践：使用用户输入作为环境变量名
        ProcessBuilder processBuilder = new ProcessBuilder("echo", "$" + envVariableName);
        processBuilder.environment().put(envVariableName, "注入的恶意值");
        processBuilder.start();
        return "环境变量命令已执行（危险：未过滤变量名）";
    }

    /**
     * 不安全示例8：文件操作结合命令执行
     * 漏洞点：将用户输入作为文件名拼接到文件操作命令中
     * 风险：攻击者可通过../等路径遍历和;等命令分隔符注入命令
     * 示例攻击输入：../etc/passwd; ls -la
     * 攻击结果：读取了系统密码文件并执行了列表命令
     */
    @GetMapping("/unsafe/file-operation")
    public String unsafeFileOperationCommand(@RequestParam String fileName) throws IOException {
        // 危险实践：文件操作命令中拼接用户输入的文件名
        String command = "cat /tmp/" + fileName; // 存在路径遍历和命令注入风险
        return "文件内容：" + RuntimeUtil.execForStr(command);
    }
}
