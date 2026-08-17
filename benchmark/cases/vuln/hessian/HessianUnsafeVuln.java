package com.jsef.benchmark.vuln;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/*
 * JSEF-Benchmark L2 — Hessian 不安全反序列化（CWE-502）
 *
 * 难度：L2（多跳）。Hessian2Input.readObject() 直接反序列化不可信字节流，
 * 未设类型白名单，可触发危险 gadget 链。
 *
 * CWE-502 (Deserialization of Untrusted Data)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 HessianUnsafeSafe.java）：读取前做类型校验 / 拒绝不可信源。
 */
public class HessianUnsafeVuln {

    /**
     * 危险路径：无白名单反序列化。
     *
     * @param hessianBytes 用户可控 Hessian 字节流
     */
    public Object read(byte[] hessianBytes) throws Exception {
        InputStream is = new ByteArrayInputStream(hessianBytes);
        com.caucho.hessian.io.Hessian2Input in = new com.caucho.hessian.io.Hessian2Input(is);
        // [CHECKPOINT id=JSEF-NV106 cwe=502 level=L2 source=hessianBytes sink=Hessian2Input.readObject expect=VULN]
        return in.readObject(); // 无白名单：不可信字节 → 任意类型实例化
    }

    public static void main(String[] args) throws Exception {
        new HessianUnsafeVuln().read(new byte[]{0x00});
    }
}
