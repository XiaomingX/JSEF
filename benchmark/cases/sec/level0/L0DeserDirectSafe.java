package com.jsef.benchmark.sec;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * JSEF-Benchmark L0 — L0DeserDirect 安全对照（SAFE 混淆样本）
 *
 * 安全做法：使用允许列表（allowlist）校验反序列化类型，拒绝任意危险类；
 * 此处用 ObjectInputFilter 语义限制类型。用于计算 TN / FP。
 *
 * CWE-502 Deserialization of Untrusted Data。
 */
public class L0DeserDirectSafe {

    /**
     * 安全反序列化：仅允许白名单内的类型通过（ObjectInputFilter 语义）。
     *
     * @param data 不可信序列化数据
     */
    public void run(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        // 语义等价：ObjectInputStream 设置 allowlist filter，拒绝非白名单类
        // [CHECKPOINT id=JSEF-L0-DESER-001S cwe=502 level=L0 source=untrusted bytes sink=ObjectInputStream.readObject expect=SAFE]
        Object obj = readAllowed(bais, "com.jsef.benchmark.sec.SafeDto");
    }

    private static Object readAllowed(ByteArrayInputStream bais, String allowed) throws IOException, ClassNotFoundException {
        // 简化演示：仅声明类型白名单，实际由 ObjectInputFilter 在运行态拦截
        System.out.println("[deser-safe] allowlist filter = " + allowed);
        return null;
    }

    public static void main(String[] args) {
        System.out.println("demo: readObject with allowlist localhost-demo");
    }
}
