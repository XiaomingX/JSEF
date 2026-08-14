package com.jsef.benchmark.sec.integrity;

import java.net.URL;
import java.net.URLClassLoader;
import java.security.CodeSigner;

/**
 * JSEF Benchmark — A08 安全对照（CWE-494，L3）
 *
 * SAFE：仅从本地受信且已签名的仓库加载插件，并校验签名/哈希后再实例化。
 */
public class UnsignedJarLoadSafe {

    /**
     * SAFE：从本地受信路径加载，并校验代码签名/完整性后才实例化。
     */
    public static void loadTrustedPlugin(String trustedPath) throws Exception {
        // source：受信的本地已签名 jar 路径
        URL url = new URL("file://" + trustedPath);
        try (URLClassLoader cl = new URLClassLoader(new URL[]{ url })) {
            Class<?> plugin = cl.loadClass("com.trusted.Plugin");
            // [CHECKPOINT id=JSEF-A08-001S cwe=494 level=L3 source=trusted signed jar sink=URLClassLoader.loadClass (signature/hash verified) expect=SAFE]
            CodeSigner[] signers = plugin.getProtectionDomain().getCodeSource().getCodeSigners();
            if (signers == null || signers.length == 0) {
                throw new SecurityException("插件未签名，拒绝加载");
            }
            plugin.getDeclaredConstructor().newInstance();
        }
    }
}
