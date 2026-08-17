package com.jsef.benchmark.vuln.longrange;

/**
 * JSEF-Benchmark L5 长程链路 2 — 网关模块（CWE-502 反序列化）
 *
 * 角色：模拟真实库前置的"接入网关 / 消息路由层"。它接收不可信 HTTP 请求体，
 * 附加一些路由元数据（tenant、topic），再把原始字节流交给下游反序列化层。
 *
 * 污点流入：不可信 HTTP 请求体（攻击者完全控制，可能是恶意序列化流）。
 * 污点流出：GatewayEnvelope.rawPayload（原样携带不可信字节流）+ 路由元数据。
 *
 * 安全底线：仅 localhost 演示，不写真实利用载荷。
 */
public class Gateway {

    /** 网关信封：携带不可信原始负载 + 路由元数据，交给下游。 */
    public static class GatewayEnvelope {
        private final byte[] rawPayload;
        private final String topic;
        private final String tenant;

        public GatewayEnvelope(byte[] rawPayload, String topic, String tenant) {
            // 污点流入点：rawPayload 直接来自不可信请求体，原样保留
            this.rawPayload = rawPayload;
            this.topic = topic;
            this.tenant = tenant;
        }

        public byte[] getRawPayload() {
            return rawPayload; // 污点从这里流出到反序列化模块
        }

        public String getTopic() {
            return topic;
        }

        public String getTenant() {
            return tenant;
        }
    }

    /**
     * 模拟网关转发：接收不可信请求体，封装成信封交给反序列化层。
     *
     * @param requestBody 不可信 HTTP 请求体字节流
     * @param topic       路由主题（来自请求头，同样不可信）
     * @return 携带不可信负载的信封
     */
    public GatewayEnvelope forward(byte[] requestBody, String topic) {
        // 中间传递点 1：不可信字节流原样进入信封
        String tenant = resolveTenant(requestBody);        // 中间传递点 2（无害路由逻辑）
        return new GatewayEnvelope(requestBody, topic, tenant);
    }

    /** 从请求体推断租户（语义桩：真实库从 JWT/Header 解析）。 */
    static String resolveTenant(byte[] body) {
        // 语义等价：从请求头/Token 解析租户
        return "tenant-default";
    }
}
