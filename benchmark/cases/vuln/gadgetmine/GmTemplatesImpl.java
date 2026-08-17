package com.jsef.benchmark.vuln.gadgetmine;

/**
 * JSEF-Benchmark L4 — fastjson gadget 挖掘验收样本 (7)(9)：TemplatesImpl 字节码注入
 * ============================================================================================
 * 验收维度（new_tool_plan_all.md §一 条件）：
 *   (7) 存在可被 getter/setter 触发的危险方法，其方法体执行危险语义；
 *   (9) 危险方法可达 = 配置/开关满足充要条件（此处需 Feature.SupportNonPublicField）。
 *
 * 根因：fastjson 在 AutoType 开启时按 `@type` 实例化任意类；当目标类为
 *   com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl 且开启
 *   SupportNonPublicField 时，攻击者可通过 `_bytecodes` 私有字段注入字节码，
 *   该类的 `getOutputProperties()` getter 在被反序列化访问时会触发
 *   `defineClass(_bytecodes)` 加载恶意类，构成无需出网的 RCE gadget 链。
 *
 * 充要可达条件（被测工具应从第一性原理判定）：
 *   1) autoTypeSupport = true（允许按 @type 实例化 TemplatesImpl）
 *   2) SupportNonPublicField = true（允许写入私有字段 _bytecodes）
 *   两者同时满足 → getOutputProperties 触发 defineClass 可达 → RULN。
 *
 * 教学占位说明：
 *   - 本文件**不 import com.alibaba.fastjson**，也不引用真实 JDK 内部类；
 *   - TemplatesImplStub 仅为 localhost 教学占位，._bytecodes 字段通过 setter 注入，
 *     getOutputProperties() 模拟调用 defineClass(_bytecodes)（注释声明语义等价
 *     com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#defineClass）。
 *   - 占位实现仅写本地 marker（不执行真实载荷、不加载任意字节码、不出网）。
 *
 * 安全底线：仅 localhost 演示语义。不引入真实 fastjson，不构造真实恶意字节码，
 * 不提供任何针对真实目标的利用脚本。VULN 侧按方法名/注释声明判定。
 *
 * 预期：VULN（expect=VULN），level=L4。
 */
public class GmTemplatesImpl {

    /**
     * 教学占位类：语义等价 com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl。
     * 仅 localhost 教学用，不执行真实 defineClass 载荷。
     */
    public static class TemplatesImplStub {

        /** 私有字节码字段：攻击者经 @type + SupportNonPublicField 注入不可信字节码。 */
        private byte[] _bytecodes;

        /**
         * setter：被 fastjson 反序列化时写入不可信 _bytecodes。
         * 语义等价 TemplatesImpl#_bytecodes 私有字段赋值。
         */
        // [CHECKPOINT id=JSEF-GM-007 cwe=502 level=L4 source=@type/_bytecodes sink=getOutputProperties->defineClass (SupportNonPublicField) expect=VULN trace=benchmark/cases/vuln/gadgetmine/GmTemplatesImpl.java:49,benchmark/cases/vuln/gadgetmine/GmTemplatesImpl.java:59,benchmark/cases/vuln/gadgetmine/GmTemplatesImpl.java:72]
        public void set_bytecodes(byte[] bc) {
            this._bytecodes = bc;   // _bytecodes setter 行：注入不可信字节码
        }

        /**
         * getter：fastjson 访问该 getter 时触发字节码定义（危险语义）。
         * 语义等价 TemplatesImpl#getOutputProperties -> defineClass(_bytecodes)。
         * @return 占位 marker
         */
        public Object getOutputProperties() {
            return defineClass(_bytecodes);   // getOutputProperties 行：触发 defineClass
        }

        /**
         * 模拟 TemplatesImpl#defineClass：按不可信 _bytecodes 定义类。
         * 占位实现仅打印本地 marker，不加载真实字节码、不出网（localhost 教学语义）。
         * @param bytecodes 不可信字节码
         * @return 占位实例
         */
        // 语义等价: com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#defineClass(byte[][])
        private Object defineClass(byte[] bytecodes) {
            // [demo-only] 仅标记可达；不执行真实 defineClass 载荷
            System.out.println("[demo-only] defineClass reached with attacker _bytecodes: " + (bytecodes != null));
            return new Object();   // defineClass sink 行：危险语义可达
        }
    }

    /**
     * 演示入口：给定 autoTypeSupport=true + SupportNonPublicField=true 配置，
     * 反序列化可实例化 TemplatesImplStub 并触发 getOutputProperties → defineClass。
     */
    public static void demo(boolean autoTypeSupport, boolean supportNonPublicField) {
        // 给定配置：autoTypeSupport=true + SupportNonPublicField=true → 可达
        if (autoTypeSupport && supportNonPublicField) {
            TemplatesImplStub stub = new TemplatesImplStub();
            stub.set_bytecodes(new byte[]{0x01});   // 模拟不可信字节码注入
            stub.getOutputProperties();             // 触发 defineClass 链
        }
    }
}
