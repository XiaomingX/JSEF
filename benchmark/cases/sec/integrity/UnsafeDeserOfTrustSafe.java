package com.jsef.benchmark.sec.integrity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.util.Set;

/**
 * JSEF Benchmark — A08 安全对照（CWE-502，L4）
 *
 * SAFE：反序列化前用类型 allowlist 校验，拒绝非预期类。
 */
public class UnsafeDeserOfTrustSafe {

    private static final Set<String> ALLOWED = Set.of(
            "com.jsef.benchmark.dto.SafePayload");

    /**
     * SAFE：仅允许 allowlist 内的类型反序列化。
     */
    public static Object deserialize(byte[] data) throws Exception {
        // source：信任边界外的不可信字节流（仍被允许，但受类型白名单约束）
        try (ObjectInputStream ois = new LookAheadOis(data)) {
            // [CHECKPOINT id=JSEF-A08-002S cwe=502 level=L4 source=untrusted bytes sink=ObjectInputStream.readObject (allowlist enforced) expect=SAFE]
            return ois.readObject();
        }
    }

    static class LookAheadOis extends ObjectInputStream {
        LookAheadOis(byte[] data) throws IOException {
            super(new ByteArrayInputStream(data));
        }
        @Override
        protected Class<?> resolveClass(java.io.ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!ALLOWED.contains(desc.getName())) {
                throw new InvalidClassException("类型不在白名单: " + desc.getName());
            }
            return super.resolveClass(desc);
        }
    }
}
