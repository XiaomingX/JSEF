package com.jsef.benchmark.vuln.tcm;

import java.lang.reflect.Method;

/**
 * TCM-1 直接类型选择（Direct Type Selection）
 * ============================================
 * 核心范式 P0 的原子体现：
 *   「攻击者控制类名/类型」 + 「系统在构造期自动调用隐式方法」 + 「隐式方法链路抵达危险 sink」
 *
 * 本样本与任何具体 JSON/序列化库无关（不出现 某json反序列化库/jackson/xstream/gson 等），
 * 仅用 Java 标准库语义（Class.forName / ClassLoader / Method.invoke / Runtime.exec）自包含复现。
 *
 * 对应 某JSON反序列化库 autotype 全局开启技巧：
 *   当反序列化器「按攻击者提供的类型名」去加载并实例化类时，
 *   若该类在构造器/getter/setter 中自带危险逻辑，则危险逻辑在构造期被自动触发。
 * 这里我们把「反序列化器」替换为最朴素的「服务端按字符串加载类」演示，
 * 从而把 autotype 的本质（类型名由攻击者控制 → 反射实例化）剥离出来。
 *
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串，不连真实远端。
 */
public class TCM1_DirectTypeSelect {

    // [VULN] L1：攻击者直接控制类名，服务端反射实例化，危险逻辑在构造器/工厂内自动执行
    public Object handleL1(String userInput) throws Exception {
        // userInput 来自 HTTP 请求体（不可信），直接作为类名
        Class<?> c = Class.forName(userInput);
        // [CHECKPOINT id=JSEF-TCM-101 cwe=502 level=L1 source=@RequestBody untrusted class name sink=Class.forName(...).newInstance() expect=VULN]
        Object o = c.getDeclaredConstructor().newInstance(); // 隐式调用构造器
        return o;
    }

    // [VULN] L3：跨方法/跨节点——从 json 解析出 cls 字段，加载并实例化后反射调用其 init() 隐式危险方法
    public Object handleL3(String json) throws Exception {
        // 极简 json 解析（自包含，不依赖任何库），提取 cls 与 arg 字段
        String cls = extractField(json, "cls");
        String arg = extractField(json, "arg"); // 占位参数 "localhost-demo"

        // 加载攻击者控制的类并实例化
        // [CHECKPOINT id=JSEF-TCM-102 cwe=502 level=L3 source=json field cls sink=ClassLoader.loadClass(...).newInstance() expect=VULN]
        Object o = ClassLoader.getSystemClassLoader().loadClass(cls).getDeclaredConstructor().newInstance();

        // 反射调用隐式危险方法 init()（演示 init 内部可达 sink，这里仅占位打印+字符串）
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
}
