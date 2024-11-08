package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class StreamApiStringController {

    // 示例 1: 将输入转换为大写
    @GetMapping("/toUpperCase")
    public List<String> toUpperCase(@RequestParam List<String> inputs) {
        return inputs.stream()
                .map(String::toUpperCase)
                .collect(Collectors.toList());
    }

    // 示例 2: 过滤长度大于3的字符串
    @GetMapping("/filterLongStrings")
    public List<String> filterLongStrings(@RequestParam List<String> inputs) {
        return inputs.stream()
                .filter(input -> input.length() > 3)
                .collect(Collectors.toList());
    }

    // 示例 3: 对输入进行排序
    @GetMapping("/sortStrings")
    public List<String> sortStrings(@RequestParam List<String> inputs) {
        return inputs.stream()
                .sorted()
                .collect(Collectors.toList());
    }

    // 示例 4: 计算字符串的总长度
    @GetMapping("/totalLength")
    public Integer totalLength(@RequestParam List<String> inputs) {
        return inputs.stream()
                .mapToInt(String::length)
                .sum();
    }

    // 示例 5: 按首字母分组字符串
    @GetMapping("/groupByFirstLetter")
    public Map<Character, List<String>> groupByFirstLetter(@RequestParam List<String> inputs) {
        return inputs.stream()
                .collect(Collectors.groupingBy(input -> input.charAt(0)));
    }

    // 示例 6: 统计每个字符串的出现次数
    @GetMapping("/countOccurrences")
    public Map<String, Long> countOccurrences(@RequestParam List<String> inputs) {
        return inputs.stream()
                .collect(Collectors.groupingBy(input -> input, Collectors.counting()));
    }
}