package com.jsef.benchmark.vuln.dbg;

import java.lang.reflect.Method;

/**
 * DBG-2 Cross-Trust-Boundary Implicit Trust (RPC 机制 DBG 原子范式)
 *
 * 对应「跨信任域 attachment 注入」类漏洞抽象：Provider 隐式信任来自对端（跨进程）
 * 的上下文/元数据（attachment），并据此执行危险操作。
 * 本文件与任何具体 RPC 框架完全解耦，仅用 Java 标准库自包含演示。
 * 仅用于 localhost 演示语义，不连接真实远端，不提供可利用的载荷脚本。
 */
public class DBG2_CrossTrustAttachment {

    /** 对端传入的 attachment 元数据 */
    public static class Attachment {
        public String callbackClass; // 对端声明的回调类名
        public byte[] payload;
    }

    // ============ L3：跨方法隐式信任 attachment ============

    /**
     * L3 间接/跨方法：服务端读取对端 attachment 中的 callbackClass 字段，
     * 并直接实例化做回调——隐式信任跨信任域传入的类名。
     */
    public void handle(Attachment att) throws Exception {
        // 行1：读取对端传入的 attachment 字段
        String callbackClass = att.callbackClass;
        // [VULN] 用对端提供的类名实例化并执行回调
        // [CHECKPOINT id=JSEF-DBG-201 cwe=913 level=L3 source=peer-supplied attachment.callbackClass sink=Class.forName(callbackClass).newInstance() expect=VULN trace=benchmark/cases/vuln/dbg/DBG2_CrossTrustAttachment.java:29,benchmark/cases/vuln/dbg/DBG2_CrossTrustAttachment.java:32]
        Object cb = Class.forName(callbackClass).getDeclaredConstructor().newInstance();
        invokeCallback(cb);
    }

    private void invokeCallback(Object cb) {
        // localhost-demo：回调执行占位
    }

    // ============ L5：gadget chain ============

    /**
     * L5 gadget chain：attachment 注入 callbackClass → 实例化 →
     * 其 init 方法通过 Method.invoke 调用 Runtime.exec，构成跨信任域可达性链。
     */

    /** 被对端指定的回调类（演示用，init 中含危险可达性） */
    public static class MaliciousCallback {
        public void init() throws Exception {
            Class<?> rt = Class.forName("java.lang.Runtime");
            Method getRuntime = rt.getMethod("getRuntime");
            Object runtime = getRuntime.invoke(null);
            Method exec = rt.getMethod("exec", String.class);
            // [VULN] gadget chain 终点：通过反射调用 Runtime.exec
            // [CHECKPOINT id=JSEF-DBG-202 cwe=913 level=L5 source=peer attachment.callbackClass sink=invoker->Runtime.exec expect=VULN trace=benchmark/cases/vuln/dbg/DBG2_CrossTrustAttachment.java:29,benchmark/cases/vuln/dbg/DBG2_CrossTrustAttachment.java:32,benchmark/cases/vuln/dbg/DBG2_CrossTrustAttachment.java:56]
            exec.invoke(runtime, "localhost-demo");
        }
    }

    /**
     * L5 链路入口：读取 attachment 的 callbackClass 并实例化，
     * 实例的 init 触发 gadget chain。
     */
    public void handleChain(Attachment att) throws Exception {
        // 行1：读取对端 attachment
        String callbackClass = att.callbackClass;
        // 行2：实例化对端指定的类
        Object cb = Class.forName(callbackClass).getDeclaredConstructor().newInstance();
        Method init = cb.getClass().getDeclaredMethod("init");
        init.invoke(cb);
    }
}
