package com.jsef.benchmark.vuln.tcm;

import java.lang.AutoCloseable;

/**
 * TCM-2 继承关系绕过白名单（Inheritance Bypass）
 * ==============================================
 * 核心范式 P0 的变体：白名单只校验「父类/接口」而非「精确类名」，
 * 攻击者可传入父类的一个危险子类，从而绕过白名单。
 *
 * 对应 某JSON反序列化库 1.2.68 expectClass 绕过技巧：
 *   当时 某JSON反序列化库 的白名单校验为「只要目标类是某个期望父类（如 AutoCloseable / Throwable）的子类即放行」，
 *   而攻击者可构造一个既是该父类子类、又在 close()/构造器中带危险逻辑的类，
 *   于是「父类白名单」被继承关系绕过，隐式 close() 触发危险 sink。
 *
 * 本样本与任何具体 JSON/序列化库无关，仅用 Java 标准库语义自包含复现。
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM2_InheritanceBypass {

    // 受信任的父类（某JSON反序列化库 1.2.68 期望父类 AutoCloseable/Throwable 的抽象）
    public interface TrustedBase extends AutoCloseable {
        void safe();
    }

    // 危险子类：它是 TrustedBase 的合法子类，但 close() 内含危险 sink
    public static class Evil implements TrustedBase {
        @Override
        public void safe() {
            System.out.println("Evil.safe (benign)");
        }

        @Override
        public void close() throws Exception {
            // [VULN] close() 被隐式调用，内部抵达危险 sink
            Runtime.getRuntime().exec("localhost-demo"); // 仅占位，不连真实远端
        }
    }

    // [VULN] L2：白名单「只检查父类」——攻击者可传 Evil（它是 TrustedBase 子类）绕过
    public void handle(String typeName) throws Exception {
        Class<?> c = Class.forName(typeName);
        if (TrustedBase.class.isAssignableFrom(c)) { // 不安全的父类白名单
            TrustedBase obj = (TrustedBase) c.getDeclaredConstructor().newInstance();
            // [CHECKPOINT id=JSEF-TCM-201 cwe=502 level=L2 source=typeName(attacker-controlled subclass) sink=TrustedBase.close()->Runtime.exec expect=VULN]
            obj.close(); // 隐式触发危险子类逻辑
        }
    }
}
