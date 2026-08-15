package com.jsef.benchmark.sec.longtask;

/**
 * JSEF-Benchmark L4（长程任务 A 组 · 成对扰动一致性镜像）— 安全对照 (CWE-502)
 * ============================================================
 * 修复方案：对应 vuln 单文件 FastjsonCrossFilePerturbed.java 的 fastjson AutoType 触发。
 * 变量重命名镜像：untrustedJson→rawPayload、typeName→clz、instantiate→build、
 * 安全方法 safeInstantiate→secureBuild。语义与原 A 组安全对照完全等价。
 *
 * 安全要点：
 *   1) 关闭 AutoType（不按攻击者控制的 @type/类名实例化任意类）；
 *   2) 使用类型白名单（allowlist）显式约束可实例化的类名；
 *   3) 任何不在白名单中的类型名直接拒绝，绝不实例化。
 *
 * 与 vuln 的区别：vuln 的 build(clz) 对不可信 clz 直接实例化；
 * 本文件在实例化前做 allowlist 校验，阻断 gadget chain 触发。
 *
 * 长程任务子目标清单 (step-by-step)：
 *   ① (见 vuln 镜像) 不可信源为 rawPayload。
 *   ② 在 safeProcess 入口即对 rawPayload 做白名单校验（安全闸）。
 *   ③ 仅白名单通过后才 secureBuild，杜绝 AutoType 任意类实例化。
 *   ④ 结论：与原 A 组安全对照一致，本样本 expect=SAFE。
 *
 * 安全底线声明：仅 localhost 演示语义，不提供真实利用脚本。
 * CWE-502 反序列化远程代码执行（已修复）。
 */
public class FastjsonCrossFilePerturbed_Safe {

    /** 受信任类型白名单（演示用，仅 localhost 占位类型）。 */
    private static final java.util.Set<String> ALLOWLIST = java.util.Set.of(
            "com.example.LocalModel",
            "com.example.SafeDto"
    );

    /**
     * 安全处理入口：接收不可信类型名，先做白名单校验。
     */
    public static Object safeProcess(String rawPayload) {
        // [CHECKPOINT id=JSEF-LT-001PS cwe=502 level=L4 source=rawPayload sink=allowlist check expect=SAFE]
        if (!ALLOWLIST.contains(rawPayload)) {   // 安全处理行：allowlist 校验
            throw new IllegalArgumentException("type not allowed: " + rawPayload);
        }
        return secureBuild(rawPayload);
    }

    /**
     * 仅在白名单通过后实例化，杜绝 AutoType 任意类实例化（CWE-502 修复）。
     */
    private static Object secureBuild(String clz) {
        System.out.println("[demo-only] safe-instantiating allowed type: " + clz);
        return new Object();
    }
}
