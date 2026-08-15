package com.jsef.benchmark.sec.tcm;

import java.lang.reflect.Method;

/**
 * TCM-1 修复（Direct Type Selection — Safe）
 * ============================================
 * 修复点：类名绝不由用户直接控制。用户只能传一个「白名单 key」，
 * 真正的目标类由服务端固定的 Map<String,Class<?>> 常量决定，
 * 攻击者无法让服务端加载任意类。
 *
 * 对应 某JSON反序列化库 autotype 关闭 / safeMode：类型名不再由反序列化数据决定，
 * 而是由服务端配置的白名单决定。
 *
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM1_DirectTypeSelect_Safe {

    // 服务端固定白名单：键由用户传，值为服务端预置、用户不可控的类
    private static final java.util.Map<String, Class<?>> ALLOWED = java.util.Map.of(
            "demo", DemoBean.class
    );

    // [SAFE] L1 修复：用户只传 key，类名由服务端映射，无法加载任意类
    public Object handleL1(String userKey) throws Exception {
        // [CHECKPOINT id=JSEF-TCM-101S cwe=502 level=L1 source=whitelist key sink=ALLOWED.get(key) expect=SAFE]
        Class<?> c = ALLOWED.get(userKey);
        if (c == null) {
            throw new IllegalArgumentException("unknown key");
        }
        Object o = c.getDeclaredConstructor().newInstance();
        return o;
    }

    // [SAFE] L3 修复：同样只用白名单 key 取类，再反射调用其 init()
    public Object handleL3(String json) throws Exception {
        String key = extractField(json, "key");
        String arg = extractField(json, "arg"); // 占位参数 "localhost-demo"

        // [CHECKPOINT id=JSEF-TCM-102S cwe=502 level=L3 source=whitelist key sink=ALLOWED.get(key).newInstance() expect=SAFE]
        Class<?> c = ALLOWED.get(key);
        if (c == null) {
            throw new IllegalArgumentException("unknown key");
        }
        Object o = c.getDeclaredConstructor().newInstance();

        Method init = o.getClass().getDeclaredMethod("init", String.class);
        init.invoke(o, arg);
        return o;
    }

    // 极简字段提取，仅用于演示，不要求健壮性
    private static String extractField(String json, String key) {
        int i = json.indexOf("\"" + key + "\"");
        if (i < 0) return "";
        int colon = json.indexOf(':', i);
        int q1 = json.indexOf('"', colon);
        int q2 = json.indexOf('"', q1 + 1);
        return json.substring(q1 + 1, q2);
    }

    // 服务端白名单内的安全类：init() 仅占位，不含危险 sink
    public static class DemoBean {
        public void init(String arg) {
            // 占位：仅打印，不执行任何危险操作
            System.out.println("DemoBean.init with arg=" + arg);
        }
    }
}
