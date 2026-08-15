/*
 * JSEF Benchmark 样本 — fastjson 版本/配置门控可达性（CWE-502 / 反序列化，长程任务 E 组）
 *
 * 教学定位：长程任务（long task）。要求分析者完成 4 个子目标：
 *   ① 识别依赖版本：类持有 fastjsonVersion 字段（如 "1.2.24"），决定 autotype 是否修补。
 *   ② 判定黑名单阈值：1.2.24 及更早版本 autotype 黑名单缺失 -> 危险；1.2.25+ 已修补。
 *   ③ 追踪版本门控危险分支：当版本低于阈值时走 isVulnerableVersion 分支，
 *      不去净化即把不可信类型名送入 JSON.parseObject，触发 autotype 危险 gadget 链。
 *   ④ 产出可达性证明：报告 2 个关键节点（版本判定行 / parseObject sink 行）。
 *
 * 可达性证明：
 *   jsonText(不可信) + fastjsonVersion("1.2.24")
 *        ──► isVulnerableVersion(version) 返回 true（低于黑名单阈值）
 *        ──► 危险分支：JSON.parseObject(jsonText, Object.class, Feature.SupportNonStringValue)
 *            开启 autotype，不可信 @type 指向危险类 -> 反序列化 gadget 执行。
 *   全程未加任何 autotype 黑名单/类型 allowlist，污点保持可达。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本，不针对真实目标生成工具。
 *           解释漏洞须紧跟修复方案（见 FastjsonVersionGated_Safe.java）。
 *
 * 注：独立 benchmark 源文件，不引入真实 fastjson 依赖，用模拟方法表达 parseObject 风格 sink。
 *     仅用于静态分析 / LLM 阅读，不强求 mvn 编译。
 */
package com.jsef.benchmark.vuln.longtask;

public class FastjsonVersionGated {

    /**
     * 模拟 JSON.parseObject 风格 sink。真实语义：
     *   com.alibaba.fastjson.JSON.parseObject(String text, Class<T> clazz)
     * 开启 autotype 时按 @type 字段反序列化任意类（localhost 演示语义，不引入真实依赖）。
     */
    static Object parseObject(String text) {
        return "parsed:" + text; // SINK（语义）
    }

    /**
     * 子目标①②：版本门控判定。低于黑名单阈值（1.2.25）视为未修补版本。
     */
    static boolean isVulnerableVersion(String version) {
        // 简化：1.2.24 及更早 -> true；1.2.25+ -> false（黑名单已补）
        return version.compareTo("1.2.25") < 0; // 版本判定节点
    }

    /**
     * 危险入口：版本门控决定 autotype 是否开启，低版本把不可信类型名送入 parseObject。
     */
    static void handleRequest(String jsonText, String fastjsonVersion) { // source：不可信 JSON + 版本字段
        if (isVulnerableVersion(fastjsonVersion)) {
            // 子目标③：危险分支，未加 autotype 黑名单，开启非字符串值支持（autotype 可达）
            // [CHECKPOINT id=JSEF-LT-006 cwe=502 level=L4 source=untrusted type under vulnerable version sink=JSON.parseObject(AutoType) expect=VULN trace=benchmark/cases/vuln/longtask/FastjsonVersionGated.java:42,benchmark/cases/vuln/longtask/FastjsonVersionGated.java:52]
            parseObject(jsonText); // autotype 开启：@type 指向危险类 -> 反序列化 gadget
        } else {
            // 安全分支：高版本默认关闭 autotype，不可信类型名无法触发 gadget
            parseObject(jsonText);
        }
    }

    public static void main(String[] args) {
        // localhost 演示：低版本 + 不可信 @type
        handleRequest("{\"@type\":\"com.demo.LocalhostDemo\",\"cmd\":\"localhost\"}", "1.2.24");
    }
}
