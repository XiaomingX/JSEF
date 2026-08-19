package com.jsef.benchmark.vuln.cascade;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * JSEF-Benchmark 样本族 B — 级联信任：隐式信任跨系统回传 URL（CWE-918，L4）
 *
 * 难度：L4（系统间级联信任 / 配置来源不可信）
 *
 * 链路（级联信任，多实体网络推理）：
 *   1) 内网服务把下游 UpstreamFetcher.fetchUrl() 的返回值当作唯一 URL 来源
 *      （source：跨系统回传、隐式信任，见 UpstreamFetcher.java:23）
 *   2) ConfigService 未做白名单 / 内网校验，直接把它作为请求目标
 *   3) HttpURLConnection.openConnection(url)                          (sink)
 *
 * 为什么是"级联信任"：系统 A（配置/编排侧）信任系统 B（上游抓取侧）返回的
 * URL 是"安全的"，把这个不可信字符串直接喂给联网组件。两个实体之间的信任
 * 关系本身缺乏证据链——B 声称的"内部白名单来源"并未在 A 侧复验。SAST 单看
 * A 侧只看到 openConnection(一个变量)，必须沿"URL 从何而来、被谁信任"的
 * 跨实体网络推理才能还原 SSRF 可达性。
 *
 * 修复要点：出口侧对 URL 做 scheme / host 白名单校验，阻断内网 / 云元数据
 * 地址（169.254.169.254 等），并对下游回传的 URL 视为不可信输入。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
public class ConfigService {

    private final UpstreamFetcher upstream = new UpstreamFetcher();

    /**
     * 危险入口：把上游回传的 URL 直接作为联网目标。
     */
    public String fetchRemoteConfig() throws Exception {
        // 入口：隐式信任下游回传的 URL（source）
        // 中间节点：跨系统回传的 URL 串（见 UpstreamFetcher.java:31）
        String url = upstream.fetchUrl();

        // [CHECKPOINT id=JSEF-OS-002 cwe=918 level=L4 source=cross-system upstream returned URL sink=HttpURLConnection.openConnection(untrusted url) expect=VULN trace=benchmark/cases/vuln/cascade/UpstreamFetcher.java:31]
        return httpGet(url); // 隐式信任：下游回传的 URL 直接发起服务端请求
    }

    /**
     * 读取系统 A 的功能开关配置（级联信任链路的配置读取节点）。
     *
     * 该配置来自不可信来源（语义桩：外部配置中心 / 可被改写的远端配置），
     * 但被 FeatureGateAdmin 视为可信 featureFlag，据此放行权限。
     *
     * @return 被不可信来源改写后的 featureFlag 值
     */
    public String readFeatureFlag() {
        // 语义等价：configClient.get("feature.admin.vault") —— 外部可改写配置
        String flag = "enabled"; // 攻击者可诱导改为 enabled 绕过开关
        System.out.println("[config] featureFlag=" + flag);
        return flag;
    }

    /**
     * 语义等价：发起服务端 HTTP GET（危险 sink，可探测内网 / 云元数据）。
     */
    static String httpGet(String url) throws Exception {
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        return br.readLine();
    }
}
