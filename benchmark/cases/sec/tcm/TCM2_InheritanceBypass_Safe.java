package com.jsef.benchmark.sec.tcm;

import java.lang.AutoCloseable;
import java.util.Set;

/**
 * TCM-2 修复（Inheritance Bypass — Safe）
 * ========================================
 * 修复点：白名单校验「精确类名」而非父类。
 *   不允许任意子类——只有服务端显式列出的类（或精确等于某个受信任基类）才放行，
 *   攻击者无法借由「父类子类关系」注入危险子类。
 *
 * 对应 某JSON反序列化库 1.2.68 修复：expectClass 校验收紧为精确类 / 显式 allowlist。
 *
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM2_InheritanceBypass_Safe {

    // 受信任的父类
    public interface TrustedBase extends AutoCloseable {
        void safe();
    }

    // 服务端显式允许的类集合（精确类名，禁止任意子类）
    private static final Set<Class<?>> ALLOWED = Set.of(TrustedBase.class, SafeImpl.class);

    // 唯一被允许的具体实现，close() 不含危险 sink
    public static class SafeImpl implements TrustedBase {
        @Override
        public void safe() {
            System.out.println("SafeImpl.safe (benign)");
        }

        @Override
        public void close() throws Exception {
            // 占位：仅清理，无危险调用
            System.out.println("SafeImpl.close (benign)");
        }
    }

    // [SAFE] L2 修复：精确类校验，禁止任意子类绕过
    public void handle(String typeName) throws Exception {
        Class<?> c = Class.forName(typeName);
        // [CHECKPOINT id=JSEF-TCM-201S cwe=502 level=L2 source=typeName sink=exact-class allowlist check expect=SAFE]
        if (c == TrustedBase.class || ALLOWED.contains(c)) {
            TrustedBase obj = (TrustedBase) c.getDeclaredConstructor().newInstance();
            obj.close();
        } else {
            throw new IllegalArgumentException("class not in exact allowlist: " + typeName);
        }
    }
}
