package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * 数值与日期输入处理控制器
 * 说明：本控制器展示了如何安全处理BigDecimal、BigInteger和LocalDate类型的用户输入，
 *       重点关注输入验证、格式规范和资源安全，避免因恶意输入或格式错误导致的安全问题。
 * 常见风险：
 * 1. 超大数值处理：恶意提交超长数字字符串可能导致内存消耗过高，引发DoS攻击
 * 2. 格式模糊性：日期等类型若不指定格式，可能因解析规则不同导致逻辑错误
 * 3. 精度失控：BigDecimal未限制精度可能导致计算资源耗尽
 * 4. 错误信息泄露：详细异常信息可能被攻击者利用
 * 安全处理原则：
 * 1. 输入长度限制：对数值字符串设置合理长度上限，防止超大输入
 * 2. 明确格式规范：日期等类型应指定具体格式，避免依赖默认解析
 * 3. 适度精度控制：根据业务需求限制BigDecimal的精度范围
 * 4. 友好错误提示：异常信息应简洁，不暴露系统实现细节
 */
@RestController
public class NumericAndDateInputController {

    // 安全常量：输入长度上限，根据业务需求调整
    private static final int MAX_NUMERIC_INPUT_LENGTH = 50;
    private static final String DATE_FORMAT = "yyyy-MM-dd"; // 明确指定日期格式

    /**
     * 处理BigDecimal类型输入
     * 功能：将用户输入的字符串安全转换为BigDecimal
     * 风险点：
     * 1. 超长输入字符串可能导致内存占用过高
     * 2. 恶意构造的数值格式可能引发解析异常
     * 安全措施：
     * - 限制输入字符串长度，防止超大数值处理
     * - 捕获格式异常并返回通用错误信息
     * @param numericInput 用户输入的数值字符串
     * @return 处理结果或错误提示
     */
    @GetMapping("/security-example/input-validation/bigdecimal")
    public String handleBigDecimalInput(@RequestParam String numericInput) {
        // 输入长度验证
        if (numericInput == null || numericInput.length() > MAX_NUMERIC_INPUT_LENGTH) {
            return "Invalid input: Input length exceeds maximum limit (" + MAX_NUMERIC_INPUT_LENGTH + " characters)";
        }

        try {
            BigDecimal inputValue = new BigDecimal(numericInput);
            return "Valid BigDecimal value: " + inputValue.toPlainString();
        } catch (NumberFormatException e) {
            return "Invalid input: Please provide a valid numeric format for BigDecimal";
        }
    }

    /**
     * 处理BigInteger类型输入
     * 功能：将用户输入的字符串安全转换为BigInteger
     * 风险点：
     * 1. 超长整数可能导致内存溢出或处理耗时过长
     * 2. 非数字格式输入可能引发解析异常
     * 安全措施：
     * - 限制输入长度，防止超大整数处理
     * - 严格验证输入格式，只接受数字字符
     * @param integerInput 用户输入的整数字符串
     * @return 处理结果或错误提示
     */
    @GetMapping("/security-example/input-validation/biginteger")
    public String handleBigIntegerInput(@RequestParam String integerInput) {
        // 输入长度与格式初步验证
        if (integerInput == null || integerInput.length() > MAX_NUMERIC_INPUT_LENGTH) {
            return "Invalid input: Input length exceeds maximum limit (" + MAX_NUMERIC_INPUT_LENGTH + " characters)";
        }
        if (!integerInput.matches("^[-+]?\\d+$")) {
            return "Invalid input: Please provide a valid integer format (only digits, optional sign)";
        }

        try {
            BigInteger inputValue = new BigInteger(integerInput);
            return "Valid BigInteger value: " + inputValue.toString();
        } catch (NumberFormatException e) {
            return "Invalid input: Failed to parse as BigInteger";
        }
    }

    /**
     * 处理LocalDate类型输入
     * 功能：将用户输入的字符串按指定格式转换为LocalDate
     * 风险点：
     * 1. 未指定格式时，默认解析规则可能随环境变化导致逻辑错误
     * 2. 恶意构造的日期字符串可能引发解析异常
     * 安全措施：
     * - 明确指定日期格式（yyyy-MM-dd），避免格式歧义
     * - 严格验证输入格式，提高解析可靠性
     * @param dateInput 用户输入的日期字符串
     * @return 处理结果或错误提示
     */
    @GetMapping("/security-example/input-validation/localdate")
    public String handleLocalDateInput(@RequestParam String dateInput) {
        // 日期格式预先说明
        if (dateInput == null || dateInput.trim().isEmpty()) {
            return "Invalid input: Date cannot be empty. Please use format: " + DATE_FORMAT;
        }

        try {
            // 明确指定日期格式，避免依赖默认解析
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(DATE_FORMAT);
            LocalDate date = LocalDate.parse(dateInput, formatter);
            return "Valid date: " + date.format(formatter);
        } catch (DateTimeParseException e) {
            return "Invalid input: Please use valid date format: " + DATE_FORMAT;
        }
    }

    /**
     * 处理带四舍五入的BigDecimal输入
     * 功能：将用户输入转换为BigDecimal并按规则四舍五入
     * 风险点：
     * 1. 超高精度数值四舍五入可能消耗大量计算资源
     * 2. 未指定舍入模式可能导致结果不一致
     * 安全措施：
     * - 限制输入长度，控制精度范围
     * - 明确指定舍入模式（HALF_UP），保证结果可预期
     * @param numericInput 用户输入的数值字符串
     * @return 处理结果或错误提示
     */
    @GetMapping("/security-example/input-validation/rounded-bigdecimal")
    public String handleRoundedBigDecimalInput(@RequestParam String numericInput) {
        // 输入长度验证
        if (numericInput == null || numericInput.length() > MAX_NUMERIC_INPUT_LENGTH) {
            return "Invalid input: Input length exceeds maximum limit (" + MAX_NUMERIC_INPUT_LENGTH + " characters)";
        }

        try {
            BigDecimal inputValue = new BigDecimal(numericInput);
            // 明确舍入模式，保留2位小数，避免默认行为导致的不可预期性
            BigDecimal roundedValue = inputValue.setScale(2, RoundingMode.HALF_UP);
            return "Rounded value (2 decimal places): " + roundedValue.toPlainString();
        } catch (NumberFormatException e) {
            return "Invalid input: Please provide a valid numeric format for BigDecimal";
        } catch (ArithmeticException e) {
            return "Processing error: Unable to round the provided number";
        }
    }
}