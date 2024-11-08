package com.freedom.securitysamples.api.thirdParty;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/fastjson")
public class JacksonController {

    // 不安全的ObjectMapper配置
    private static final ObjectMapper unsafeMapper = new ObjectMapper()
            .enableDefaultTyping() // 危险：启用默认类型
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

    // 示例1：不安全的通用反序列化端点
    @PostMapping("/unsafe/deserialize")
    public Object unsafeDeserialize(@RequestBody String jsonInput) {
        try {
            // 危险：直接反序列化用户输入而没有类型限制
            return unsafeMapper.readValue(jsonInput, Object.class);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }

    // 示例2：使用enableDefaultTyping的不安全配置
    @PostMapping("/unsafe/polymorphic")
    public BaseClass unsafePolymorphic(@RequestBody String jsonInput) {
        try {
            // 危险：使用多态反序列化
            return unsafeMapper.readValue(jsonInput, BaseClass.class);
        } catch (IOException e) {
            return null;
        }
    }

    // 示例3：不安全的Map反序列化
    @PostMapping("/unsafe/map")
    public Map<String, Object> unsafeMapDeserialize(@RequestBody String jsonInput) {
        try {
            // 危险：Map中可能包含任意类型
            return unsafeMapper.readValue(jsonInput, Map.class);
        } catch (IOException e) {
            return null;
        }
    }

    // 示例4：不安全的动态类型加载
    @PostMapping("/unsafe/dynamic")
    public Object unsafeDynamicType(@RequestBody String jsonInput, @RequestParam String className) {
        try {
            // 危险：动态加载用户指定的类
            Class<?> clazz = Class.forName(className);
            return unsafeMapper.readValue(jsonInput, clazz);
        } catch (Exception e) {
            return null;
        }
    }

    // 示例5：不安全的嵌套对象反序列化
    @PostMapping("/unsafe/nested")
    public NestedObject unsafeNestedDeserialize(@RequestBody String jsonInput) {
        try {
            // 危险：嵌套对象可能包含恶意payload
            return unsafeMapper.readValue(jsonInput, NestedObject.class);
        } catch (IOException e) {
            return null;
        }
    }

    // 安全的实现示例

    private static final ObjectMapper safeMapper = new ObjectMapper()
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
            .activateDefaultTyping(
                    BasicPolymorphicTypeValidator.builder()
                            .allowIfBaseType(Object.class) // 允许所有对象类型
                            .build(),
                    ObjectMapper.DefaultTyping.NON_FINAL // 指定默认类型为非最终类型
            );

    @PostMapping("/safe/deserialize")
    public SafeObject safeDeserialize(@RequestBody String jsonInput) {
        try {
            // 安全：使用具体类型，禁用多态
            return safeMapper.readValue(jsonInput, SafeObject.class);
        } catch (IOException e) {
            return null;
        }
    }

    // 相关的数据类
    public static class BaseClass {
        public String data;
    }

    public static class NestedObject {
        public Object nestedData;
        public Map<String, Object> properties;
    }

    public static class SafeObject {
        private String safeData;
        // 仅包含安全的基本类型
        private int number;

        // Getters and Setters
        public String getSafeData() {
            return safeData;
        }

        public void setSafeData(String safeData) {
            this.safeData = safeData;
        }

        public int getNumber() {
            return number;
        }

        public void setNumber(int number) {
            this.number = number;
        }
    }
}