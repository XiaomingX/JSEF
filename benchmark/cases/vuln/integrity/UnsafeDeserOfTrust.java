package com.jsef.benchmark.vuln.integrity;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

/**
 * JSEF Benchmark — A08 软件与数据完整性失败（CWE-502，L4）
 *
 * 场景：在信任边界内直接反序列化外部输入，未对目标类型做任何 allowlist 校验。
 *
 * 为何危险：反序列化入口若接收不可信字节流，攻击者可构造 gadget chain 执行
 * 任意代码。跨信任边界反序列化是 A08（完整性）与 A08 反序列化的典型交集。
 *
 * 安全底线：仅 localhost 演示语义，不写真实 gadget chain 利用脚本。
 */
public class UnsafeDeserOfTrust {

    /**
     * VULN：直接反序列化不可信字节流，无类型 allowlist 校验。
     */
    public static Object deserialize(byte[] data) throws Exception {
        // source：信任边界外的不可信字节流
        // [CHECKPOINT id=JSEF-A08-002 cwe=502 level=L4 source=untrusted bytes sink=ObjectInputStream.readObject (no allowlist) expect=VULN]
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
}
