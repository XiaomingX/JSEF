package com.jsef.benchmark.sec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/*
 * JSEF-Benchmark L2 — Hessian 反序列化修复（CWE-502）
 *
 * 修复：对来源做校验 / 仅接受可信来源，并在 readObject 前校验期望类型。
 *
 * CWE-502 (Deserialization of Untrusted Data)。
 */
public class HessianUnsafeSafe {

    static final java.util.Set<String> ALLOWED = java.util.Set.of("com.jsef.dto.SafeDto");

    /**
     * 安全路径：仅解析可信来源，且类型受白名单约束。
     *
     * @param hessianBytes 用户可控 Hessian 字节流
     */
    public Object read(byte[] hessianBytes, boolean trustedSource) throws Exception {
        if (!trustedSource) {
            throw new SecurityException("untrusted source rejected");
        }
        InputStream is = new ByteArrayInputStream(hessianBytes);
        com.caucho.hessian.io.Hessian2Input in = new com.caucho.hessian.io.Hessian2Input(is);
        Object obj = in.readObject();
        if (obj != null && !ALLOWED.contains(obj.getClass().getName())) {
            throw new SecurityException("type not allowed");
        }
        // [CHECKPOINT id=JSEF-NV106S cwe=502 level=L2 source=hessianBytes sink=Hessian2Input.readObject (after trusted-source + type allowlist) expect=SAFE]
        return obj; // 仅可信来源 + 白名单类型
    }

    public static void main(String[] args) throws Exception {
        new HessianUnsafeSafe().read(new byte[]{0x00}, true);
    }
}
