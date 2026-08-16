package com.jsef.benchmark.sec;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * CWE-502 修复：保持 autotype 关闭，反序列化为受控目标类型。
 */
@RestController
public class FastjsonAutoTypeOnSafe {

    @PostMapping("/api/v1/fastjson/safe/parse")
    public Map<String, Object> parse(@RequestBody String untrustedJson) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false); // 关闭 autotype
        // [CHECKPOINT id=JSEF-COMP-010S cwe=502 level=L2 source=@RequestBody untrustedJson sink=JSON.parseObject(Map) autotype off expect=SAFE]
        return JSON.parseObject(untrustedJson, Map.class); // 仅映射到已知类型
    }
}
