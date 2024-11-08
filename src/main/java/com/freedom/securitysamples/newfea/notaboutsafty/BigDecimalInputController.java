package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;

@RestController
public class BigDecimalInputController {

    @GetMapping("/bigdecimal")
    public String handleBigDecimal(@RequestParam String userInput) {
        try {
            // 注意：直接将用户输入转换为 BigDecimal 可能会带来安全风险，例如导致不期望的格式化错误或潜在的DoS攻击。
            BigDecimal input = new BigDecimal(userInput);
            return "The inputted BigDecimal is: " + input.toString();
        } catch (NumberFormatException e) {
            return "Invalid input for BigDecimal.";
        }
    }

    @GetMapping("/biginteger")
    public String handleBigInteger(@RequestParam String userInput) {
        try {
            // 注意：直接将用户输入转换为 BigInteger 可能会带来安全风险，例如导致不期望的格式化错误或潜在的DoS攻击。
            BigInteger input = new BigInteger(userInput);
            return "The inputted BigInteger is: " + input.toString();
        } catch (NumberFormatException e) {
            return "Invalid input for BigInteger.";
        }
    }

    @GetMapping("/localdate")
    public String handleLocalDate(@RequestParam String userInput) {
        try {
            // 注意：直接将用户输入转换为 LocalDate 可能会带来解析错误。
            LocalDate date = LocalDate.parse(userInput);
            return "The inputted LocalDate is: " + date.toString();
        } catch (DateTimeParseException e) {
            return "Invalid input for LocalDate.";
        }
    }

    @GetMapping("/roundbigdecimal")
    public String handleRoundedBigDecimal(@RequestParam String userInput) {
        try {
            // 注意：直接将用户输入转换为 BigDecimal 可能会带来安全风险，例如导致不期望的格式化错误或潜在的DoS攻击。
            BigDecimal input = new BigDecimal(userInput);
            // 默认情况下对 BigDecimal 进行四舍五入，保留两位小数。
            BigDecimal roundedInput = input.setScale(2, RoundingMode.HALF_UP);
            return "The rounded BigDecimal is: " + roundedInput.toString();
        } catch (NumberFormatException e) {
            return "Invalid input for BigDecimal.";
        }
    }
}
