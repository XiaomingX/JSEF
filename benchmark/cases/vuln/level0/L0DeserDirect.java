package com.jsef.benchmark.vuln;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.IOException;

/**
 * JSEF-Benchmark L0 — 基线（不安全反序列化，单跳直连）
 *
 * 难度：L0（基线）。source 直接传入 sink，无中间变量。
 * 用于校准 TP 基线与定位精度（CAP-03 入门级）。
 *
 * CWE-502 Deserialization of Untrusted Data。
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 */
public class L0DeserDirect {

    /**
     * 单跳：不可信字节流直接反序列化（sink）。
     *
     * @param data 不可信序列化数据（类比 HTTP param serializedData）
     */
    public void run(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        // [CHECKPOINT id=JSEF-L0-DESER-001 cwe=502 level=L0 source=untrusted bytes sink=ObjectInputStream.readObject expect=VULN]
        Object obj = ois.readObject();
    }

    public static void main(String[] args) {
        System.out.println("demo: readObject from localhost-demo bytes");
    }
}
