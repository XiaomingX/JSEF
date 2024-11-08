package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;
import java.util.function.Function;

@RestController
@RequestMapping("/newfeature")
public class NewFeatureController {

    @GetMapping("/map")
    public String mapInput(@RequestParam String input) {
        // 使用Java的lambda表达式处理用户输入
        Function<String, String> mappingFunction = s -> "Mapped: " + s.toUpperCase();
        return mappingFunction.apply(input);
    }

    @GetMapping("/optional")
    public String optionalInput(@RequestParam Optional<String> input) {
        // 使用Java的Optional特性处理用户输入
        return input.map(s -> "Optional Mapped: " + s.toUpperCase())
                .orElse("No input provided");
    }
}
