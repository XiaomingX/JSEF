package com.jsef.benchmark.vuln.longtask;

import java.util.Map;

/**
 * JSEF-Benchmark L4（长程任务 A 组）— fastjson AutoType 跨类触发（CWE-502 不安全的反序列化）
 * ============================================================
 * 子目标：跨文件全局追踪（需要同时分析 A / B / C 三个编译单元才能得出结论）。
 *
 * 长程任务子目标清单 (step-by-step)：
 *   ① 定位不可信源：本文件（文件 A）的 HTTP 入口方法参数 `untrustedJson`，
 *      即 Spring `@RequestBody` 注入的不可信 JSON 字符串。
 *   ② 追踪跨文件字段传递：文件 A 把 `untrustedJson` 写入 Transport 对象的
 *      `typeName` 字段（文件 B），再由文件 B 的 getter 读出并回传。
 *   ③ 确认 sink 实例化不可信类型：文件 C 的 sink 方法对传回的 `typeName`
 *      调用模拟的 `JSON.parseObject(AutoType)` 风格实例化 —— autotype 开启时
 *      会按 `@type`/类名实例化任意类，构成 gadget chain 触发点。
 *   ④ 产出 gadget 链节点序列（trace）：
 *      benchmark/cases/vuln/longtask/FastjsonCrossFile_A_Source.java:28   // 不可信源入口
 *      benchmark/cases/vuln/longtask/FastjsonCrossFile_B_Transport.java:24 // 字段流入(typeName)
 *      benchmark/cases/vuln/longtask/FastjsonCrossFile_B_Transport.java:38 // 字段流出(getter)
 *      benchmark/cases/vuln/longtask/FastjsonCrossFile_C_Sink.java:30      // sink 实例化
 *
 * 预期可达性证明中间产物（trace 节点，file:line）：
 *   A:28 -> B:24 -> B:38 -> C:30
 *
 * 安全底线声明：仅 localhost 演示语义。本文件不提供任何真实攻击利用脚本，
 * 不构造针对真实目标的 fastjson 利用链，所有 Payload 均为教学占位字符串。
 */
public class FastjsonCrossFile_A_Source {

    /**
     * 文件 A — 不可信源入口。
     *
     * untrustedJson 来自外部 HTTP 请求体，攻击者可控制其中的 `@type`/类名。
     * 此处为模拟，不依赖真实 fastjson 依赖。
     */
    public static void handleRequest(String untrustedJson) {
        // [VULN] 不可信 JSON 字符串从此处进入系统，作为污点源头
        // 下一行即 trace 节点 A:28 —— 污点进入点
        Transport transport = new Transport();
        transport.setTypeName(untrustedJson);   // A:28 污点写入传输对象字段

        // 跨编译单元：将承载污点的 transport 交给文件 C 处理
        FastjsonCrossFile_C_Sink.process(transport);
    }
}
