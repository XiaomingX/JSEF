package com.jsef.benchmark.vuln.longtask;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * JSEF-Benchmark C组（longtask）— Shiro RememberMe 反序列化链 可达性还原 (CWE-502, L5)
 *
 * ============================================================================
 * 题材：Apache Shiro ≤1.2.4 的 rememberMe 反序列化漏洞（CVE-2016-4437）的**抽象与自包含演示**。
 * 用标准库模拟整条数据通路，不涉及真实 AES 密钥 / 不读真实 Cookie：
 *   rememberMe Cookie ──► Base64 解码 ──► AES 解密（自带硬编码密钥语义）──► 反序列化 ──► 危险 gadget
 *
 * 难度定位：L5（gadget chain 可达性还原）。每个独立环节都"看似无害"：
 *   Base64 解码、AES 解密、readObject 都是通用机制。
 * 但当它们串成"Cookie -> 解密 -> 直接 ObjectInputStream.readObject"的链路时，
 * 不可信 Cookie 就能把任意 gadget 负载注入反序列化入口 —— 危险可达性形成。
 *
 * 纯语法 SAST 难以识别"解密后即直接反序列化不可信字节"的危险组合，需跨函数/跨调用还原链路。
 *
 * ----------------------------------------------------------------------------
 * 子目标清单（要求被测对象还原整条链路节点序列）：
 *   ① 识别 rememberMe Cookie 入口：请求中携带的 Base64 字符串即不可信源。
 *   ② 追踪 Base64 -> AES 解密：decode 后进入 decrypt（模拟硬编码密钥解密）。
 *   ③ 确认反序列化触发：decrypt 后的字节直接交 ObjectInputStream.readObject。
 *   ④ 产出链路节点序列（可达性证明，见下方 REACHABILITY 产物）：
 *        rememberMe cookie (Base64)
 *          -> Base64.getDecoder().decode
 *          -> AES/ECB/PKCS5Padding 解密（硬编码密钥语义）
 *          -> ObjectInputStream.readObject   ★ SINK
 *
 * 可达性证明中间产物（REACHABILITY）：
 *   untrusted_cookie ──► Base64.decode ──► AES.decrypt ──► ObjectInputStream.readObject ★ SINK
 *   （readObject 对任意 gadgets 可达；此处用占位对象演示反序列化入口，不执行真实利用）
 *
 * 安全底线：本文件仅演示"解密后直接反序列化不可信字节"的危险组合语义，仅 localhost 演示，
 *   不提供真实 Padding Oracle 利用 / 不写针对真实目标的利用脚本。具体修复见 sec 对照。
 *
 * CWE-502 反序列化远程代码执行（Shiro rememberMe 链路）。
 * ============================================================================
 */
public class ShiroRememberMeGadget {

    /**
     * 模拟 Shiro 的 rememberMe 处理：Base64 -> AES 解密 -> 直接反序列化。
     * 注意：AES 密钥在此抽象为硬编码常量语义（真实 Shiro 默认密钥已公开），
     * 但本演示不实现真实加解密，仅用占位字节流表示"解密后的不可信对象字节"。
     */
    public static Object processRememberMe(String rememberMeCookie) {
        // ① 不可信源：rememberMe Cookie（Base64 字符串）
        byte[] decoded = Base64.getDecoder().decode(rememberMeCookie);                 // 52

        // ② 模拟 AES 解密：以硬编码密钥语义解开密文，得到原始对象字节（不可信）
        byte[] decrypted = aesDecrypt(decoded);                                        // 55

        // ③ 反序列化触发：解密后的不可信字节直接交给 ObjectInputStream.readObject
        // [CHECKPOINT id=JSEF-LT-004 cwe=502 level=L5 source=rememberMe cookie (decrypted bytes) sink=ObjectInputStream.readObject expect=VULN trace=benchmark/cases/vuln/longtask/ShiroRememberMeGadget.java:52,benchmark/cases/vuln/longtask/ShiroRememberMeGadget.java:55]
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decrypted))) {
            return ois.readObject(); // ★ SINK：对任意 gadget 可达
        } catch (Exception e) {
            throw new RuntimeException("localhost-demo: deserialization entry reached", e);
        }
    }

    /** 模拟 AES/ECB/PKCS5Padding 解密（仅占位：返回还原后的字节流，不实现真实算法）。 */
    static byte[] aesDecrypt(byte[] ciphertext) {
        // 占位：真实场景此处用硬编码密钥解密；演示仅原样透传表示"已解密字节"
        return ciphertext;
    }

    public static void main(String[] args) {
        // 仅演示链路可达性，不连接真实网络/不使用真实 Cookie 与密钥
        // 传入一个 Base64 占位串，仅用于触发 readObject 入口演示
        processRememberMe("localhost-demo-placeholder");
    }
}
