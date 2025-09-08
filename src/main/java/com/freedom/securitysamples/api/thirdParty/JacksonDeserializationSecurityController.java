package com.freedom.securitysamples.api.thirdParty;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

/**
 * Jackson反序列化安全漏洞示例控制器
 * 说明：JSON反序列化漏洞是指攻击者通过构造恶意JSON数据，在应用程序反序列化过程中
 *       执行未授权的代码或操作，可能导致远程代码执行、服务器被控制等严重安全事件。
 * 常见风险：
 * 1. 远程代码执行（RCE）：最严重的风险，攻击者可执行任意系统命令
 * 2. 服务器信息泄露：通过反序列化获取敏感系统信息
 * 3. 拒绝服务攻击：构造特殊对象导致系统资源耗尽
 * 4. 权限提升：通过操纵反序列化过程绕过安全检查
 * 修复原则：
 * 1. 使用最新版本的Jackson库，及时修复已知漏洞
 * 2. 禁用默认类型解析（enableDefaultTyping已不安全）
 * 3. 严格限制反序列化的目标类型，避免使用Object等通用类型
 * 4. 使用类型验证器（PolymorphicTypeValidator）限制允许的类型
 * 5. 避免反序列化不可信的输入数据
 */
@RestController
@RequestMapping("/security-example/deserialization")
public class JacksonDeserializationSecurityController {

    /**
     * 不安全的ObjectMapper配置
     * 漏洞点：
     * 1. 启用了enableDefaultTyping()，这会在JSON中包含类型信息
     * 2. 允许反序列化为任意类型，为攻击者提供了注入恶意对象的可能
     * 风险：攻击者可构造包含危险类（如java.lang.Runtime）的JSON，执行系统命令
     */
    private static final ObjectMapper UNSAFE_OBJECT_MAPPER = new ObjectMapper()
            .enableDefaultTyping() // 高危：启用默认类型解析，已在Jackson 2.10+中标记为过时
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

    /**
     * 不安全示例1：通用类型反序列化端点
     * 漏洞点：
     * 1. 接收任意JSON输入
     * 2. 反序列化为Object类型，允许任何类的实例化
     * 攻击示例：
     * 发送包含恶意类信息的JSON，如：
     * {"@class":"java.lang.Runtime","name":"calc.exe"}
     * 可能导致远程代码执行
     */
    @PostMapping("/unsafe/general-object")
    public Object unsafeDeserializeToGeneralObject(@RequestBody String jsonInput) {
        try {
            // 危险：反序列化为Object类型，没有任何类型限制
            return UNSAFE_OBJECT_MAPPER.readValue(jsonInput, Object.class);
        } catch (IOException e) {
            return "反序列化错误: " + e.getMessage();
        }
    }

    /**
     * 不安全示例2：多态类型反序列化
     * 漏洞点：
     * 1. 使用了不安全的ObjectMapper配置
     * 2. 允许反序列化为BaseClass的任何子类（包括恶意构造的类）
     * 风险：攻击者可构造继承自BaseClass的恶意类，执行恶意代码
     */
    @PostMapping("/unsafe/polymorphic-type")
    public BaseClass unsafePolymorphicDeserialization(@RequestBody String jsonInput) {
        try {
            // 危险：在不安全配置下进行多态反序列化
            return UNSAFE_OBJECT_MAPPER.readValue(jsonInput, BaseClass.class);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 不安全示例3：Map类型反序列化
     * 漏洞点：
     * 1. 反序列化为Map<String, Object>，值可以是任意类型
     * 2. 攻击者可在Map中嵌入恶意对象
     * 风险：Map中的值可被反序列化为危险类型，导致安全问题
     */
    @PostMapping("/unsafe/map-type")
    public Map<String, Object> unsafeMapDeserialization(@RequestBody String jsonInput) {
        try {
            // 危险：Map的值可以是任意类型，为注入攻击提供可能
            return UNSAFE_OBJECT_MAPPER.readValue(jsonInput, Map.class);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 不安全示例4：动态类型加载反序列化
     * 漏洞点：
     * 1. 允许用户指定要反序列化的类名
     * 2. 动态加载类并进行反序列化
     * 风险：攻击者可指定系统中存在的危险类进行实例化，执行恶意操作
     */
    @PostMapping("/unsafe/dynamic-type")
    public Object unsafeDynamicTypeDeserialization(
            @RequestBody String jsonInput, 
            @RequestParam String className) {
        try {
            // 极度危险：完全信任用户输入的类名并动态加载
            Class<?> targetClass = Class.forName(className);
            return UNSAFE_OBJECT_MAPPER.readValue(jsonInput, targetClass);
        } catch (Exception e) {
            return "错误: " + e.getMessage();
        }
    }

    /**
     * 不安全示例5：嵌套对象反序列化
     * 漏洞点：
     * 1. NestedObject包含Object类型的字段
     * 2. 这些字段可被反序列化为任意类型
     * 风险：攻击者可在嵌套对象中注入恶意类实例
     */
    @PostMapping("/unsafe/nested-object")
    public NestedObject unsafeNestedObjectDeserialization(@RequestBody String jsonInput) {
        try {
            // 危险：嵌套对象中的Object字段可被反序列化为任意类型
            return UNSAFE_OBJECT_MAPPER.readValue(jsonInput, NestedObject.class);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 安全的ObjectMapper配置
     * 安全措施：
     * 1. 使用BasicPolymorphicTypeValidator限制允许的类型
     * 2. 精确控制允许反序列化的类型范围
     * 3. 禁用了不安全的默认类型解析，改用更安全的activateDefaultTyping
     */
    private static final ObjectMapper SAFE_OBJECT_MAPPER = new ObjectMapper()
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
            .activateDefaultTyping(
                    // 严格的类型验证器，只允许指定的基础类型
                    BasicPolymorphicTypeValidator.builder()
                            .allowIfBaseType(SafeObject.class) // 仅允许SafeObject及其子类
                            .allowIfBaseType(String.class)     // 允许String类型
                            .allowIfBaseType(Integer.class)    // 允许Integer类型
                            .build(),
                    ObjectMapper.DefaultTyping.NON_FINAL // 仅对非final类启用类型信息
            );

    /**
     * 安全示例：严格限制类型的反序列化
     * 安全措施：
     * 1. 使用安全配置的ObjectMapper
     * 2. 明确指定反序列化的目标类型为SafeObject
     * 3. SafeObject只包含基本数据类型，无危险操作
     */
    @PostMapping("/safe/specific-type")
    public SafeObject safeSpecificTypeDeserialization(@RequestBody String jsonInput) {
        try {
            // 安全：只反序列化为指定的安全类型
            return SAFE_OBJECT_MAPPER.readValue(jsonInput, SafeObject.class);
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 基础数据类，用于展示多态反序列化风险
     */
    public static class BaseClass {
        public String data;
        
        // Getters and Setters
        public String getData() { return data; }
        public void setData(String data) { this.data = data; }
    }

    /**
     * 嵌套对象类，用于展示嵌套反序列化风险
     * 注意：包含Object类型字段会增加安全风险
     */
    public static class NestedObject {
        public Object nestedData;          // 危险：Object类型可被反序列化为任意对象
        public Map<String, Object> properties; // 危险：Map的值可以是任意类型
        
        // Getters and Setters
        public Object getNestedData() { return nestedData; }
        public void setNestedData(Object nestedData) { this.nestedData = nestedData; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }

    /**
     * 安全的数据类，仅包含基本类型字段
     * 遵循最小权限原则，只包含必要的字段和方法
     */
    public static class SafeObject {
        private String safeData;  // 安全：字符串类型
        private int number;       // 安全：基本数值类型
        
        // Getters and Setters - 只提供必要的访问方法
        public String getSafeData() { return safeData; }
        public void setSafeData(String safeData) { this.safeData = safeData; }
        public int getNumber() { return number; }
        public void setNumber(int number) { this.number = number; }
    }
}
