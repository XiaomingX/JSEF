package com.freedom.securitysamples.api.jsonpCallback;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class JsonpController {

    // 1. 直接拼接callback参数(原始漏洞)
    @GetMapping("/jsonp/bad01")
    public String jsonp01(String callback){
        return callback + "{'msg':'success'}";
    }

    // 2. 使用format格式化拼接,同样存在注入
    @GetMapping("/jsonp/bad02")
    public String jsonp02(String callback){
        return String.format("%s({'msg':'success'})", callback);
    }

    // 3. 使用StringBuilder拼接,仍然不安全
    @GetMapping("/jsonp/bad03")
    public String jsonp03(String callback){
        StringBuilder sb = new StringBuilder();
        sb.append(callback).append("({'msg':'success'})");
        return sb.toString();
    }

    // 4. 返回JSON对象但未校验callback
    @GetMapping("/jsonp/bad04")
    public String jsonp04(String callback){
        Map<String,Object> result = new HashMap<>();
        result.put("msg", "success");
        return callback + "(" + JSON.toJSONString(result) + ")";
    }

    // 5. 使用@ResponseBody但未限制callback
    @GetMapping("/jsonp/bad05")
    @ResponseBody
    public String jsonp05(String callback, String param){
        return callback + "('" + param + "')";
    }

    // 6. 多参数拼接导致的注入
    @GetMapping("/jsonp/bad06")
    public String jsonp06(String callback, String name, String value){
        return callback + "({'name':'" + name + "','value':'" + value + "'})";
    }

    // 7. 动态函数名称导致的注入
    @GetMapping("/jsonp/bad07")
    public String jsonp07(String callback, String funcName){
        return callback + "." + funcName + "({'msg':'success'})";
    }

    // 8. 错误的参数编码处理
    @GetMapping("/jsonp/bad08")
    public String jsonp08(String callback){
        String result = "<script>alert(1)</script>";
        return callback + "('" + result + "')";
    }

    // 9. 缺少Content-Type限制
    @GetMapping("/jsonp/bad09")
    public String jsonp09(String callback){
        return callback + "(" + System.getProperty("user.dir") + ")";
    }

    // 10. 动态引入外部资源
    @GetMapping("/jsonp/bad10")
    public String jsonp10(String callback, String url){
        return callback + "('" + url + "')";
    }
}