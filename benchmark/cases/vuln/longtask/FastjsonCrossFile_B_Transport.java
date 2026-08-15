package com.jsef.benchmark.vuln.longtask;

/**
 * JSEF-Benchmark L4（长程任务 A 组）— 中间传输类（文件 B）
 * ============================================================
 * 角色：跨文件污点传递的"中转站"。文件 A 把不可信 `typeName` 写入本类的
 * 字段，文件 C 通过本类的 getter 读出该字段并送入 sink。
 *
 * 长程任务子目标清单 (step-by-step)：
 *   ① (见文件 A) 不可信源在文件 A 的 untrustedJson。
 *   ② 追踪跨文件字段传递：本文件 `typeName` 字段承接污点（set 入），
 *      再经 getter 流出（get 出）。仅看本文件无法判断源是否可信，
 *      必须回到文件 A 与文件 C 串联分析。
 *   ③ (见文件 C) sink 实例化。
 *   ④ (见文件 C) 产出 trace 节点序列。
 *
 * 预期可达性证明中间产物（trace 节点，file:line）：
 *   A:28 -> B:24 -> B:38 -> C:30
 *
 * 安全底线声明：仅 localhost 演示语义，不提供真实利用；本字段承载的
 * 是教学占位字符串，不代表任何真实 fastjson 利用载荷。
 */
public class FastjsonCrossFile_B_Transport {

    /** 承接不可信类型名的字段；污点经此跨文件流动。 */
    private String typeName;

    /**
     * 字段流入点（set 入污点）。
     * trace 节点 B:24 —— 污点从此进入传输对象。
     */
    public void setTypeName(String typeName) {
        this.typeName = typeName;   // B:24 污点写入字段
    }

    /**
     * 字段流出点（get 出污点），供文件 C 读取。
     * trace 节点 B:38 —— 污点从此离开传输对象前往 sink。
     */
    public String getTypeName() {
        return this.typeName;   // B:38 污点流出字段
    }
}
