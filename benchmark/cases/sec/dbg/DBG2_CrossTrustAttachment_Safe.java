package com.jsef.benchmark.sec.dbg;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/**
 * DBG-2 Cross-Trust-Boundary Implicit Trust — 安全修复版
 *
 * 修复策略：attachment 中的类名走服务端白名单，或回调实例由服务端预置。
 * 与任何具体 RPC 框架解耦，仅用 Java 标准库自包含演示。
 * 仅用于 localhost 演示语义。
 */
public class DBG2_CrossTrustAttachment_Safe {

    public static class Attachment {
        public String callbackClass;
        public byte[] payload;
    }

    /** 服务端预置的合法回调类名白名单 */
    private static final List<String> ALLOWED_CALLBACKS =
            Arrays.asList("com.jsef.benchmark.sec.dbg.SafeCallbackA");

    // ============ L3：attachment 类名走服务端白名单 ============

    /**
     * L3 修复：对端 attachment 中的类名必须经过服务端白名单校验，
     * 不在名单内则拒绝，绝不按对端指定实例化。
     */
    public void handle(Attachment att) throws Exception {
        String callbackClass = att.callbackClass;
        // [SAFE] 类名受服务端白名单约束，跨信任域输入不再隐式信任
        // [CHECKPOINT id=JSEF-DBG-201S cwe=913 level=L3 source=peer attachment sink=server allowlist callback expect=SAFE]
        if (!ALLOWED_CALLBACKS.contains(callbackClass)) {
            throw new SecurityException("callback class not allowed: " + callbackClass);
        }
        Object cb = Class.forName(callbackClass).getDeclaredConstructor().newInstance();
        invokeCallback(cb);
    }

    private void invokeCallback(Object cb) {
        // localhost-demo：回调执行占位
    }

    // ============ L5：回调实例由服务端预置 ============

    /**
     * L5 修复：不读取对端 attachment 中的 callbackClass，
     * 回调实例由服务端预置，彻底切断 gadget chain 的入口。
     */
    public void handleChain(Attachment att) throws Exception {
        // [SAFE] 回调实例由服务端预置，对端无法注入类名
        // [CHECKPOINT id=JSEF-DBG-202S cwe=913 level=L5 source=peer attachment sink=server-prebuilt callback expect=SAFE]
        Object cb = new SafeCallbackA();
        Method init = cb.getClass().getDeclaredMethod("init");
        init.invoke(cb);
    }

    /** 服务端预置的安全回调 */
    public static class SafeCallbackA {
        public void init() {
            // localhost-demo：仅执行安全逻辑，无 Runtime.exec 可达性
        }
    }
}
