/*
 * JSEF Benchmark 样本 — 隐式信任内部输入：内部服务数据未校验直接 eval/反序列化（VulnGym 子类 BL-TRUST-BOUNDARY，CWE-94/502，L3）
 * 独立 benchmark 源文件，不强求编译。安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点：漏洞核心在"信任边界语义"——系统默认内部服务调用方可信，未校验其回传数据即直接 eval/反序列化。
 * 一旦内网被入侵或上游被篡改，内部输入即成攻击源。数据流干净，但信任边界假设错误。静态分析需在
 * eval(payload) 处识别"来自内部服务的数据未经边界校验即进入危险 sink"。
 */
package com.jsef.benchmark.vuln;

public class TrustInternalInput {

    // 演示用：内部服务响应
    static final class InternalResp { final String payload; InternalResp(String p){ this.payload=p; } }

    // 危险：直接把内部服务返回当表达式执行，无边界校验
    static Object handle(InternalResp resp) {
        // source：内部服务回传 payload（跨信任边界，攻击者可通过上游注入）
        // [CHECKPOINT id=JSEF-V1-TRU-001 cwe=94 level=L3 source=internal-service response payload sink=ScriptEngine.eval(payload) (no boundary check) expect=VULN]
        return new javax.script.ScriptEngineManager().getEngineByName("js").eval(resp.payload);
    }
}
