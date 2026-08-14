package com.jsef.benchmark.vuln.integrity;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * JSEF Benchmark — A08 软件与数据完整性失败（CWE-494，L3）
 *
 * 场景：从不可信/远程 http 地址动态加载未签名 jar 并实例化类。
 *
 * 为何危险：加载来源与内容均未校验签名/完整性，攻击者若劫持该 URL 即可
 * 注入任意字节码并执行，构成远程代码执行。属于"信任边界内加载不可信代码"。
 *
 * 安全底线：仅 localhost 演示语义，不写真实劫持/投毒利用脚本。
 */
public class UnsignedJarLoad {

    /**
     * VULN：从远程 http 地址加载未签名 jar 并实例化类。
     */
    public static void loadRemotePlugin(String pluginUrl) throws Exception {
        // source：不可信的远程 http 资源地址
        // [CHECKPOINT id=JSEF-A08-001 cwe=494 level=L3 source=untrusted http URL sink=URLClassLoader.loadClass (unsigned jar) expect=VULN]
        URLClassLoader cl = new URLClassLoader(new URL[]{ new URL(pluginUrl) });
        Class<?> plugin = cl.loadClass("com.evil.Plugin");
        plugin.getDeclaredConstructor().newInstance();
    }
}
