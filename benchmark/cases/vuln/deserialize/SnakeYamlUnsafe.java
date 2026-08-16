/*
 * JSEF Benchmark 样本 — SnakeYAML 不安全反序列化 (CWE-502, L3)
 * 使用默认 Yaml.load 解析不可信 YAML，!! 标签可实例化任意类。
 * 安全底线：仅 localhost 演示语义。
 */
package com.jsef.benchmark.vuln;

import org.yaml.snakeyaml.Yaml;

public class SnakeYamlUnsafe {

    static Object fromYaml(String yamlText) {
        Yaml yaml = new Yaml(); // 默认构造器允许任意标签
        // [CHECKPOINT id=JSEF-EXT-020 cwe=502 level=L3 source=untrusted yaml sink=Yaml.load expect=VULN]
        return yaml.load(yamlText); // !! 标签实例化任意类
    }
}
