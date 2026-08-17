package com.jsef.benchmark.vuln.longrange;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 长程链路 2 — 入口 / 持久化模块（CWE-502 反序列化）
 *
 * 角色：模拟真实库的分层入口控制器。污点从不可信 HTTP 请求体出发，
 * 经 3 个编译单元、>= 5 个中间传递点，最终到达"持久化/执行" sink，
 * 触发危险 getter（Jackson 多态 materialize 出的对象或被存入仓库时的 getter）。
 *
 * 链路（跳数 >= 5）：
 *   1) HTTP @RequestBody bytes + @RequestHeader topic   (source：不可信)
 *   2) Gateway.forward(bytes, topic)                    -> 信封（中间节点 1，Gateway.java:46）
 *   3) env.getRawPayload()                              -> 不可信字节流（中间节点 2，Gateway.java:30）
 *   4) Deserializer.deserialize(env)                    -> readTree + treeToValue（中间节点 3，Deserializer.java:46）
 *   5) mapper.treeToValue(node, Object.class)           -> 多态 materialize（中间节点 4，Deserializer.java:49）
 *   6) 入口把对象存入仓库 -> 危险 getter 触发              -> sink（本文件）
 *
 * 为什么是 L5（gadget chain 级）：单独看 Gateway 转发、Deserializer 读树、
 * 持久化 save 都"像正常功能"；但当不可信字节流被 Gateway 原样收下、再由
 * 开启多态类型的 Deserializer materialize、最后被持久化层触发其 getter 时，
 * 跨 网关/反序列化/持久化 三模块的组合才形成反序列化可达性。纯语法 SAST
 * 难以识别这种跨模块组合危险。
 *
 * 安全底线：仅 localhost 演示，不写真实利用载荷。
 *
 * CWE-502 Deserialization of Untrusted Data。
 */
@RestController
public class EntryDeser {

    private final Gateway gateway = new Gateway();
    private final Deserializer deserializer = new Deserializer();
    private final Repository repo = new Repository();

    @PostMapping("/benchmark/longrange/deser/unsafe")
    public String handle(@RequestBody byte[] requestBody,
                         @RequestHeader("X-Topic") String topic) {
        // 入口：不可信请求体 + 路由头进入链路
        Gateway.GatewayEnvelope env = gateway.forward(requestBody, topic); // 传递点 2（见 Gateway.java:46）
        Object obj = deserializer.deserialize(env);                        // 传递点 3-5（见 Deserializer.java:46,49）

        // [CHECKPOINT id=JSEF-LR-002 cwe=502 level=L5 source=@RequestBody bytes sink=persisted object triggers dangerous getter expect=VULN trace=benchmark/cases/vuln/longrange/Gateway.java:52,benchmark/cases/vuln/longrange/Gateway.java:30,benchmark/cases/vuln/longrange/Deserializer.java:39,benchmark/cases/vuln/longrange/Deserializer.java:42]
        return repo.save(obj); // 持久化 -> 触发反序列化对象危险 getter（sink）
    }

    /** 语义等价：把反序列化对象存入仓库，触发其 getter/初始化逻辑（危险 sink）。 */
    static class Repository {
        String save(Object obj) {
            // 语义等价：jpaRepository.save(obj) / cache.put(obj)
            // 触发 obj 的危险 getter（如 Jackson 多态指定类的 @JsonCreator）
            System.out.println("[persist] " + obj);
            return "saved:" + obj;
        }
    }
}
