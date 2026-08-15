package com.jsef.benchmark.sec.tcm;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * TCM-3 修复（Parser Cache Bypass — Safe）
 * ========================================
 * 修复点：
 *   1) L3：每次解析都重新校验类型，缓存中绝不保存原始类型字符串——
 *      只缓存「已通过校验的安全对象引用」，re-parse 时复用安全对象而非类型名。
 *   2) L5：彻底不缓存类型；invoker 链末端仅在类型被本次解析重新校验通过后才允许执行。
 *
 * 对应 某JSON反序列化库 2.0.x 修复：denyList / 白名单在每次解析（含 re-parse、缓存命中）时
 * 都重新生效，类型字符串不进入可被绕过的缓存。
 *
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM3_ParserCacheBypass_Safe {

    // 缓存「已校验的安全对象」，而非类型字符串
    private final Map<String, Object> safeCache = new HashMap<>();

    // 服务端白名单——只允许无害类型
    private static boolean isAllowed(String type) {
        return "com.jsef.benchmark.sec.tcm.DemoBean".equals(type);
    }

    /**
     * L3 修复：每次解析都重新校验类型，缓存不含类型字符串。
     */
    public void handle(String payload) throws Exception {
        String type = extractType(payload);
        // [SAFE] 每次解析都重新校验，缓存只存安全对象
        // [CHECKPOINT id=JSEF-TCM-301S cwe=502 level=L3 source=payload sink=re-validate each parse expect=SAFE]
        if (!isAllowed(type)) {
            throw new IllegalArgumentException("type rejected by re-validation: " + type);
        }
        // 缓存的是已校验对象，而非类型字符串，re-parse 复用安全对象
        Object safeObj = safeCache.computeIfAbsent(type, (k) -> new DemoBean());
        System.out.println("re-parsed (safe): " + safeObj);
    }

    // 简单抽取 payload 中的 @type 值（localhost 演示用，不解析真实 JSON）
    private static String extractType(String payload) {
        if (payload != null && payload.contains("@type=")) {
            return payload.substring(payload.indexOf("@type=") + 6).trim();
        }
        return "com.jsef.benchmark.sec.tcm.DemoBean";
    }

    /**
     * L5 修复：不缓存类型；invoker 链末端仅在本次解析重新校验通过后才执行。
     */
    public void handleChain(String payload) throws Exception {
        String type = extractType(payload);
        // [SAFE] 无缓存类型绕过：本次解析重新校验
        // [CHECKPOINT id=JSEF-TCM-302S cwe=502 level=L5 source=payload sink=no cache type bypass expect=SAFE]
        if (!isAllowed(type)) {
            throw new IllegalArgumentException("type rejected, no cache bypass: " + type);
        }

        Function<String, Object> invoker = (t) -> {
            try {
                // 即便到达链末端，也只针对已校验类型；Runtime.exec 不再被任意类型驱动
                Class<?> rt = Class.forName("java.lang.Runtime");
                java.lang.reflect.Method getRuntime = rt.getMethod("getRuntime");
                Object runtime = getRuntime.invoke(null);
                java.lang.reflect.Method exec = rt.getMethod("exec", String.class);
                // 此处的 exec 仅对白名单内 DemoBean 触发，且为本省占位，不再受缓存绕过影响
                return exec.invoke(runtime, "localhost-demo"); // 仅占位，不连真实远端
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        invoker.apply(type);
    }

    // 无害演示 Bean（仅用于白名单命中分支）
    public static class DemoBean {
        @Override
        public String toString() {
            return "DemoBean(benign)";
        }
    }
}
