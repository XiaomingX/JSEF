package com.jsef.benchmark.vuln;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-502 Fastjson autotype 开启（教学级触发点演示，不含利用链）：
 * 当 ParserConfig.getGlobalInstance().setAutoTypeSupport(true) 开启后，
 * 反序列化会按 @type 字段实例化任意类，配合内置/三方 gadget 可触发危险行为。
 * 本样本仅展示"开启 autotype + 反序列化不可信 JSON"的 sink 触发点，
 * 不含任何可用 gadget 链或可连接恶意地址。
 *
 * 修复（见 sec）：保持 autotype 关闭，使用指定类反序列化或白名单 TypeReference。
 */
@RestController
public class FastjsonAutoTypeOn {

    @PostMapping("/api/v1/fastjson/unsafe/parse")
    public Object parse(@RequestBody String untrustedJson) {
        com.alibaba.fastjson.parser.ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        // [CHECKPOINT id=JSEF-COMP-010 cwe=502 level=L2 source=@RequestBody untrustedJson sink=JSON.parseObject (autotype on) expect=VULN]
        return JSON.parseObject(untrustedJson); // autotype 开启，可实例化任意 @type
    }
}
