package com.freedom.securitysamples.api.thirdParty;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class FastjsonController {

    // 示例1：不安全的parseObject使用
    @PostMapping("/unsafe1")
    public String unsafeParseObject(@RequestBody String jsonStr) {
        // 不安全：直接使用parseObject而没有关闭autotype
        Object obj = JSON.parseObject(jsonStr);
        return "处理结果：" + obj.toString();
    }

    // 示例2：启用了autotype的不安全配置
    @PostMapping("/unsafe2")
    public String unsafeAutoType(@RequestBody String jsonStr) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        Object obj = JSON.parseObject(jsonStr);
        return "处理结果：" + obj.toString();
    }

    // 示例3：不安全的parse方法
    @PostMapping("/unsafe3")
    public String unsafeParse(@RequestBody String jsonStr) {
        // 不安全：使用parse方法同样可能导致反序列化漏洞
        Object obj = JSON.parse(jsonStr);
        return "处理结果：" + obj.toString();
    }

    // 示例4：特征配置不当
    @PostMapping("/unsafe4")
    public String unsafeFeature(@RequestBody String jsonStr) {
        // 不安全：启用了SupportNonPublicField特征
        Object obj = JSON.parseObject(jsonStr, Feature.SupportNonPublicField);
        return "处理结果：" + obj.toString();
    }

    // 示例5：泛型反序列化不当
    @PostMapping("/unsafe5")
    public String unsafeGeneric(@RequestBody String jsonStr) {
        // 不安全：使用泛型反序列化时未proper
        Map<String, Object> map = JSON.parseObject(jsonStr, Map.class);
        return "处理结果：" + map.toString();
    }

    // 示例6：TypeReference使用不当
    @PostMapping("/unsafe6")
    public String unsafeTypeReference(@RequestBody String jsonStr) {
        // 不安全：使用TypeReference但未限制类型
        Object obj = JSON.parseObject(jsonStr, Object.class);
        return "处理结果：" + obj.toString();
    }

    // 安全的使用方式示例
    @PostMapping("/safe")
    public String safeUsage(@RequestBody String jsonStr) {
        // 安全：指定具体类型，关闭autoType
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
        // 安全：使用具体的目标类型
        JSONObject jsonObject = JSON.parseObject(jsonStr, JSONObject.class);
        return "安全处理结果：" + jsonObject.toString();
    }

    // 安全的反序列化示例
    @PostMapping("/safe2")
    public String safeDeserialization(@RequestBody String jsonStr) {
        try {
            // 1. 设置安全的解析配置
            ParserConfig config = new ParserConfig();
            config.setSafeMode(true);

            // 2. 使用白名单方式
            config.addAccept("com.freedom.securitysamples.model.");

            // 3. 指定具体的目标类型
            JSONObject result = JSON.parseObject(jsonStr, JSONObject.class, config);

            return "安全处理结果：" + result.toString();
        } catch (Exception e) {
            return "错误：非法的JSON格式或未授权的类型";
        }
    }

    // 处理特定对象的安全示例
    @PostMapping("/safe3")
    public String safeSpecificObject(@RequestBody String jsonStr) {
        try {
            // 1. 禁用autoType
            ParserConfig.getGlobalInstance().setAutoTypeSupport(false);

            // 2. 使用具体的数据传输对象
            UserDTO userDTO = JSON.parseObject(jsonStr, UserDTO.class);

            // 3. 进行输入验证
            if (userDTO != null && userDTO.validate()) {
                return "有效的用户数据：" + userDTO.toString();
            } else {
                return "无效的用户数据";
            }
        } catch (Exception e) {
            return "数据处理错误：" + e.getMessage();
        }
    }
}

// 用于安全示例的数据传输对象
class UserDTO {
    private String username;
    private String email;

    // getter和setter方法
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    // 数据验证方法
    public boolean validate() {
        return username != null && !username.isEmpty()
                && email != null && email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
    }

    @Override
    public String toString() {
        return "UserDTO{" +
                "username='" + username + '\'' +
                ", email='" + email + '\'' +
                '}';
    }
}