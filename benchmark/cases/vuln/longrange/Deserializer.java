package com.jsef.benchmark.vuln.longrange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * JSEF-Benchmark L5 长程链路 2 — 反序列化模块（CWE-502 反序列化）
 *
 * 角色：模拟真实库的"反序列化/对象映射层"。从网关信封取出不可信字节流，
 * 用开启了多态类型（enableDefaultTyping / @JsonTypeInfo）的 ObjectMapper
 * 读成 JsonNode 并最终 materialize 成具体对象。真实库常用它做跨服务消息
 * 解码 / 缓存值还原。
 *
 * 污点流入：GatewayEnvelope.rawPayload（来自 Gateway，攻击者控制）。
 * 污点流出：materialize 后的对象（其危险 getter 在反序列化期间即被触发，
 *          或对象被传给持久化层后触发危险 getter）。
 *
 * 危险点：开启 Jackson 多态类型 + 不可信输入 = 攻击者可指定任意类
 * （如恶意 gadget 的 @JsonCreator / getter），反序列化即触发危险逻辑。
 * 若使用原生 readObject（注释处）则直接落到 Serializable 任意 gadget chain。
 *
 * 安全底线：仅 localhost 演示，不写真实利用载荷。
 */
public class Deserializer {

    // 真实库常见危险配置：开启默认多态类型（等价于 enableDefaultTyping）
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * 把不可信信封里的字节流反序列化成对象。
     *
     * @param env 携带不可信负载的网关信封
     * @return 反序列化得到的对象（可能触发危险 getter）
     */
    public Object deserialize(Gateway.GatewayEnvelope env) {
        byte[] payload = env.getRawPayload();                 // 中间传递点 3（污点进入反序列化）
        try {
            // 中间传递点 4：不可信字节流被读成 JsonNode 树
            JsonNode node = mapper.readTree(payload);         // 语义等价：ObjectMapper.readTree(payload)
            // 中间传递点 5：多态 materialize 成具体类（危险：类型由不可信数据指定）
            // 语义等价：mapper.readValue(payload, Object.class) 且开启多态类型
            Object materialized = mapper.treeToValue(node, Object.class);
            return materialized;
        } catch (Exception e) {
            // 退化到原生反序列化（同样危险）：ObjectInputStream.readObject()
            // 语义等价：ois.readObject()
            return fallbackRaw(payload);
        }
    }

    /** 退化路径：原生反序列化（语义桩）。 */
    private Object fallbackRaw(byte[] payload) {
        // 语义等价：new ObjectInputStream(...).readObject()
        System.out.println("[deser-fallback] " + payload.length + " bytes");
        return payload;
    }
}
