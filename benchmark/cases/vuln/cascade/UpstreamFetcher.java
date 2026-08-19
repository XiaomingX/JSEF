package com.jsef.benchmark.vuln.cascade;

/**
 * JSEF-Benchmark 样本族 B — 级联信任：上游抓取服务桩（中间层）
 *
 * 角色：模拟系统 B 的"上游抓取器"。本文件不设独立 checkpoint，
 * 仅作为 ConfigService 级联信任链路的 trace 节点存在。
 *
 * 污点流：fetchUrl() 返回一个声称来自"内部白名单配置"的 URL 字符串。
 * 该字符串被系统 A（ConfigService）无条件信任并直接作为联网目标，
 * 形成跨系统隐式信任的 SSRF。
 *
 * 为什么这里是合理非缺陷：辅助类不单独计 checkpoint，它只是主链路上的
 * 一个传递节点；真正的判定点（sink）在 ConfigService。被测工具应沿
 * 级联信任链把本文件的返回值识别为"不可信跨系统输入"。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
public class UpstreamFetcher {

    /**
     * 返回一个跨系统回传的 URL 字符串（语义桩：模拟上游服务响应）。
     *
     * @return 攻击者可诱导的 URL（此处声称来自内部配置，实际不可信）
     */
    public String fetchUrl() {
        // 语义等价：restTemplate.getForObject("http://upstream/config-url", String.class)
        // 或内部服务返回"推荐配置源地址"；该字符串未经验证。
        String url = "http://config.internal/v1/remote"; // 跨系统回传、攻击者可注入
        System.out.println("[upstream] returns url");
        return url;
    }
}
