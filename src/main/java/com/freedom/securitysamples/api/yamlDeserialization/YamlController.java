package com.freedom.securitysamples.api.yamlDeserialization;

import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;

@RestController
@RequestMapping("/api")
public class YamlController {

    // 原有的不安全示例1
    @GetMapping("/yaml/processPayload01")
    public String processYamlPayloadV1(String yamlPayload) throws IOException {
        Yaml yamlParser = new Yaml();
        Object loadedObject = yamlParser.loadAs(yamlPayload, null);
        return "success";
    }

    // 原有的不安全示例2
    @GetMapping("/yaml/processPayload02")
    public String processYamlPayloadV2(String yamlPayload) throws IOException {
        Yaml yamlParser = new Yaml();
        Object loadedObject = yamlParser.load(yamlPayload);
        return "success";
    }

    // 不安全示例3：直接从请求体读取YAML
    @PostMapping("/yaml/processPayload03")
    public String processYamlPayloadV3(@RequestBody String yamlPayload) {
        Yaml yamlParser = new Yaml();
        Object result = yamlParser.load(new StringReader(yamlPayload));
        return "processed";
    }

    // 不安全示例4：使用通用构造器
    @GetMapping("/yaml/processPayload04")
    public String processYamlPayloadV4(String yamlPayload) {
        Yaml yamlParser = new Yaml(new Constructor());
        Object result = yamlParser.load(yamlPayload);
        return "processed";
    }

    // 不安全示例5：从输入流读取
    @PostMapping("/yaml/processPayload05")
    public String processYamlPayloadV5(InputStream inputStream) {
        Yaml yamlParser = new Yaml();
        Object result = yamlParser.load(inputStream);
        return "processed";
    }

    // 不安全示例6：使用loadAll方法
    @GetMapping("/yaml/processPayload06")
    public String processYamlPayloadV6(String yamlPayload) {
        Yaml yamlParser = new Yaml();
        Iterable<Object> documents = yamlParser.loadAll(yamlPayload);
        return "processed";
    }

    // 不安全示例7：使用parse方法
    @GetMapping("/yaml/processPayload07")
    public String processYamlPayloadV7(String yamlPayload) {
        Yaml yamlParser = new Yaml();
        StringReader reader = new StringReader(yamlPayload);
        Object result = yamlParser.parse(reader);
        return "processed";
    }
}