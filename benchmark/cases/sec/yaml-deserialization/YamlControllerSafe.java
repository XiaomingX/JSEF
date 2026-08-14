// [SAFE]
// 安全对照：YAML 反序列化（修复版）
// 修复原则：使用 SafeConstructor / 受限类型白名单解析 YAML，禁止反序列化任意类。
//          本示例使用 org.yaml.snakeyaml.constructor.SafeConstructor 解析，避免 RCE。
package com.jsef.benchmark.sec;

import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * 安全示例：使用 SafeConstructor 解析 YAML，限制类型实例化。
 */
@RestController
@RequestMapping("/api")
public class YamlControllerSafe {

    // 安全示例1：使用 SafeConstructor 加载 YAML，禁止构造危险对象
    @GetMapping("/yaml/safe/processPayload01")
    public String safeProcessYamlPayloadV1(String yamlPayload) {
        Yaml yamlParser = new Yaml(new SafeConstructor());
        // [CHECKPOINT id=JSEF-YAML-001S cwe=502 level=L1 source=@RequestParam yamlPayload sink=Yaml.loadAs (SafeConstructor, no arbitrary class) expect=SAFE]
        Object loadedObject = yamlParser.loadAs(yamlPayload, Object.class);
        return "success";
    }

    // 安全示例2：使用 SafeConstructor 的 load 方法
    @GetMapping("/yaml/safe/processPayload02")
    public String safeProcessYamlPayloadV2(String yamlPayload) {
        Yaml yamlParser = new Yaml(new SafeConstructor());
        // [CHECKPOINT id=JSEF-YAML-002S cwe=502 level=L1 source=@RequestParam yamlPayload sink=Yaml.load (SafeConstructor, no arbitrary class) expect=SAFE]
        Object loadedObject = yamlParser.load(yamlPayload);
        return "success";
    }
}
