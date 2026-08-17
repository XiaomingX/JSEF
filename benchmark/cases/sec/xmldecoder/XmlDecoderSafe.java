package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L2 — XMLDecoder 反序列化修复
 *
 * 修复：不解析不可信 XML（本项目改用显式结构化解析 / 拒绝未知来源）。
 *
 * CWE-502 (Deserialization of Untrusted Data)。
 */
public class XmlDecoderSafe {

    /**
     * 安全路径：拒绝解析不可信 XML。
     *
     * @param userXml 用户可控 XML
     */
    public Object load(String userXml) {
        // [CHECKPOINT id=JSEF-NV104S cwe=502 level=L2 source=userXml sink=XMLDecoder.readObject (rejected / not used) expect=SAFE]
        throw new UnsupportedOperationException("untrusted XML not deserialized"); // 不解析不可信 XML
    }
}
