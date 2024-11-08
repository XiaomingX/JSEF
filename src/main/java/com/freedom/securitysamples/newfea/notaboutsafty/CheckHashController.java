package com.freedom.securitysamples.newfea.notaboutsafty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class CheckHashController {

    // 存在潜在风险的hash处理示例
    @GetMapping("/addToHash")
    public String addToHash(@RequestParam(name = "input") String input) {
        // 警告：以下代码存在潜在的DoS风险
        // 用户提供的输入被直接用作HashMap的key，可能导致哈希碰撞攻击，造成拒绝服务。
        Map<String, String> hashMap = new HashMap<>();
        hashMap.put(input, "someValue");

        return "Input has been added to the hash map.";
    }
}