package com.jsef.benchmark.sec.longtask;

import java.util.Base64;

/**
 * JSEF-Benchmark C组（longtask）— Shiro RememberMe 反序列化链 安全对照 (CWE-502, L5)
 *
 * ============================================================================
 * 修复对照：对应 vuln/longtask/ShiroRememberMeGadget.java 的 SAFE 版本。
 *
 * 修复要点：斩断"解密后直接反序列化不可信字节"的危险组合。两种安全做法择一：
 *   做法 A（不反序列化）：rememberMe 仅用于身份标识，服务端用签名/HMAC 校验后读取
 *        结构化字段，根本不调用 ObjectInputStream.readObject。
 *   做法 B（类白名单）：若必须反序列化，使用 ObjectInputStream 子类并覆写
 *        resolveClass，仅允许受信类（allowlist），拒绝任意 gadget 类。
 *
 * 子目标呼应（对照验证 SAFE）：
 *   ① 入口仍为 rememberMe Cookie，但仅做校验/结构化解析。
 *   ② Base64 -> AES 解密后，不直接进入反序列化。
 *   ③ 触发点：不走 ObjectInputStream.readObject，或经 allowlist 受控反序列化。
 *   ④ 可达性证明：untrusted_cookie -> decode -> decrypt -> 受信解析/类白名单（无 SINK）。
 *
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷/脚本。
 * CWE-502 反序列化远程代码执行（已修复）。
 * ============================================================================
 */
public class ShiroRememberMeGadget_Safe {

    /**
     * 安全版：rememberMe 解密后仅做受信处理，不反序列化任意对象。
     * 这里用"类白名单 + 结构化解析"语义演示：解析出用户标识字段即止，
     * 绝不把不可信字节交给 ObjectInputStream.readObject。
     */
    public static String processRememberMeSafe(String rememberMeCookie) {
        // ① 入口：rememberMe Cookie（Base64 字符串）
        byte[] decoded = Base64.getDecoder().decode(rememberMeCookie);                 // 36

        // ② 模拟 AES 解密（带随机/外部托管密钥语义，非硬编码默认密钥）
        byte[] decrypted = aesDecryptSafe(decoded);                                    // 39

        // ③ 安全处理：仅做受信结构化解析（如读取 userId 字段），不反序列化任意对象
        //    等价于不调用 ObjectInputStream.readObject，或经 allowlist 受控反序列化
        // [CHECKPOINT id=JSEF-LT-004S cwe=502 level=L5 source=rememberMe cookie sink=validated/non-serialized expect=SAFE]
        String userId = parseTrustedFields(decrypted);
        return userId; // 受信字段，无危险可达性
    }

    /** 模拟 AES 解密（安全版：密钥外部托管、非默认硬编码密钥）。 */
    static byte[] aesDecryptSafe(byte[] ciphertext) {
        // 占位：演示仅原样透传，强调密钥管理改进而非算法本身
        return ciphertext;
    }

    /** 受信结构化解析：仅提取白名单内字段，绝不 readObject 任意类型。 */
    static String parseTrustedFields(byte[] data) {
        // 演示：只读取预定义长度的标识字段，拒绝任意 gadget 类
        return "trusted-user-from-allowlist";
    }

    public static void main(String[] args) {
        processRememberMeSafe("localhost-demo-placeholder");
    }
}
