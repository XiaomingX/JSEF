package com.jsef.benchmark.vuln.longtask;

import java.util.Map;

/**
 * JSEF-Benchmark L4（长程任务 A 组 · 成对扰动一致性镜像）— fastjson AutoType 单文件重写 (CWE-502)
 * ============================================================
 * 本文件是 FastjsonCrossFile_A/B/C 三文件跨类逻辑的**语义等价但结构扰动**镜像：
 *   - 三文件合并为单文件，变量名全部重命名（untrustedJson→rawPayload、typeName→clz、
 *     Transport→Carrier、instantiate→build）。
 *   - 包名保持 com.jsef.benchmark.vuln.longtask，与原 A 组一致（不跨包，仅单文件内流动）。
 *   - 污点流与可达性与原 A 组完全等价：rawPayload(不可信源) → Carrier.clz 字段
 *     → build(clz) 按不可信类名实例化（autotype 风格）。
 *
 * 长程任务子目标清单 (step-by-step)：
 *   ① 定位不可信源：handle(rawPayload)，rawPayload 为外部 HTTP 请求体（模拟 @type/类名可控）。
 *   ② 追踪字段传递：setClz(rawPayload) 写入 Carrier.clz，getClz() 读出，全在单文件内。
 *   ③ 确认 sink 实例化不可信类型：build(clz) 模拟 JSON.parseObject(AutoType) 风格实例化。
 *   ④ 产出 gadget 链节点序列（trace）：
 *      benchmark/cases/vuln/longtask/FastjsonCrossFilePerturbed.java:58   // 不可信源入口(setClz)
 *      benchmark/cases/vuln/longtask/FastjsonCrossFilePerturbed.java:72   // sink 实例化(build)
 *
 * 预期可达性证明中间产物（trace 节点，file:line）：
 *   :58 -> :72
 *
 * 安全底线声明：仅 localhost 演示语义。本文件不提供任何真实攻击利用脚本，
 * 不构造针对真实目标的 fastjson 利用链，所有 Payload 均为教学占位字符串。
 */
public class FastjsonCrossFilePerturbed {

    /**
     * 中间传输载体（对应原 B 文件 Transport），字段 clz 承接污点。
     */
    static class Carrier {
        private String clz;

        /** 字段流入点（set 入污点）。trace 节点 :41。 */
        void setClz(String clz) {
            this.clz = clz;   // :41 污点写入字段
        }

        /** 字段流出点（get 出污点）。trace 节点 :46。 */
        String getClz() {
            return this.clz;   // :46 污点流出字段
        }
    }

    /**
     * 不可信源入口（对应原 A 文件 handleRequest）。
     * rawPayload 来自外部 HTTP 请求体，攻击者可控制其中的 @type/类名。
     * trace 节点 :58 —— 污点进入点。
     */
    public static void handle(String rawPayload) {
        // [VULN] 不可信 JSON 字符串从此处进入系统，作为污点源头
        Carrier carrier = new Carrier();
        carrier.setClz(rawPayload);   // :58 污点写入传输对象字段

        // 单文件内：直接将承载污点的 carrier 送入 sink 处理
        process(carrier);
    }

    /**
     * sink 方法（对应原 C 文件 process）：取回不可信 clz 并实例化。
     * trace 节点 :72 为最终 sink 行（:69 取回污点）。
     */
    public static void process(Carrier carrier) {
        String clz = carrier.getClz();   // :69 从字段取回污点

        // [CHECKPOINT id=JSEF-LT-001P cwe=502 level=L4 source=rawPayload(type field) sink=JSON.parseObject(AutoType) expect=VULN trace=benchmark/cases/vuln/longtask/FastjsonCrossFilePerturbed.java:58,benchmark/cases/vuln/longtask/FastjsonCrossFilePerturbed.java:72]
        Object instance = build(clz);   // :72 sink：按不可信类名实例化
    }

    /**
     * 模拟 JSON.parseObject(AutoType) 风格的类型自动实例化。
     * 不依赖真实 fastjson；仅打印类名以表达语义。安全实现见对应 _Safe 文件。
     */
    private static Object build(String clz) {
        // 模拟：autotype 开启时按 clz 实例化任意类
        System.out.println("[demo-only] instantiating type: " + clz);
        return new Object();
    }
}
