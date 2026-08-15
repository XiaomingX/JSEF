package com.jsef.benchmark.vuln.longtask;

/**
 * JSEF-Benchmark L4（长程任务 A 组）— 最终 sink（文件 C）
 * ============================================================
 * 角色：跨文件污点到达点。从文件 B 的 getter 取回不可信 `typeName`，
 * 调用模拟的 `JSON.parseObject(AutoType)` 风格实例化方法 —— autotype 开启时，
 * 会按攻击者控制的类名实例化任意类，构成 CWE-502 触发点。
 *
 * 长程任务子目标清单 (step-by-step)：
 *   ① (见文件 A) 不可信源在文件 A 的 untrustedJson。
 *   ② (见文件 B) 污点经 Transport.typeName 字段跨文件传递。
 *   ③ 确认 sink 实例化不可信类型：本文件 `process` 调用 `instantiate`，
 *      对不可信 `typeName` 做类型自动实例化。
 *   ④ 产出 gadget 链节点序列（trace）：
 *      A:28 -> B:24 -> B:38 -> C:30
 *
 * 预期可达性证明中间产物（trace 节点，file:line）：
 *   A:28 -> B:24 -> B:38 -> C:30
 *
 * 安全底线声明：仅 localhost 演示语义。本文件不提供任何真实攻击利用脚本，
 * 不构造针对真实目标的 fastjson 利用链；instantiate 为模拟方法，仅做
 * 类名打印以表达"按不可信类型名实例化"的语义。
 */
public class FastjsonCrossFile_C_Sink {

    /**
     * sink 方法：接收跨文件传来的 transport，取出不可信 typeName 并实例化。
     */
    public static void process(FastjsonCrossFile_B_Transport transport) {
        String typeName = transport.getTypeName();   // C:21 从跨文件字段取回污点

        // [CHECKPOINT id=JSEF-LT-001 cwe=502 level=L4 source=untrustedJson(type field) sink=JSON.parseObject(AutoType) expect=VULN trace=benchmark/cases/vuln/longtask/FastjsonCrossFile_A_Source.java:28,benchmark/cases/vuln/longtask/FastjsonCrossFile_B_Transport.java:24,benchmark/cases/vuln/longtask/FastjsonCrossFile_B_Transport.java:38,benchmark/cases/vuln/longtask/FastjsonCrossFile_C_Sink.java:30]
        Object instance = instantiate(typeName);   // C:30 sink：按不可信类型名实例化
    }

    /**
     * 模拟 JSON.parseObject(AutoType) 风格的类型自动实例化。
     * 不依赖真实 fastjson；仅打印类名以表达语义。安全实现见 sec 包对照。
     */
    private static Object instantiate(String typeName) {
        // 模拟：autotype 开启时按 typeName 实例化任意类
        System.out.println("[demo-only] instantiating type: " + typeName);
        return new Object();
    }
}
