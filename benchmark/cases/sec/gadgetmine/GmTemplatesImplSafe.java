package com.jsef.benchmark.sec.gadgetmine;

/**
 * JSEF-Benchmark L4 — fastjson gadget 挖掘安全对照 (7)(9)：TemplatesImpl 不可达
 * ============================================================================================
 * 安全对照（对应 JSEF-GM-007）：同一 TemplatesImplStub 占位类，但**未满足充要可达条件**，
 * 因此 defineClass 不可达，gadget 链被阻断。
 *
 * 阻断条件（满足任一即安全）：
 *   A) 未开启 Feature.SupportNonPublicField → 私有字段 _bytecodes 无法被写入，
 *      攻击者无法注入字节码，defineClass 无可操作载荷；
 *   B) 字段只读校验 / 拒绝不可信 _bytecodes → setter 被安全态拦截。
 *
 * 教学占位说明：
 *   - 不 import com.alibaba.fastjson；TemplatesImplStub 与 vuln 侧语义一致，
 *     但 SAFE 侧**按实现判定**：set_bytecodes 在缺少 SupportNonPublicField 时
 *     拒绝写入，getOutputProperties 不会触发真实 defineClass 语义。
 *
 * 安全底线：仅 localhost 演示语义。不引入真实 fastjson，不构造真实恶意字节码。
 * SAFE 侧按真实实现判定（字段写入被拒）。
 *
 * 预期：SAFE（expect=SAFE），level=L4。
 */
public class GmTemplatesImplSafe {

    /**
     * 教学占位类：语义等价 TemplatesImpl（同 vuln 侧结构）。
     */
    public static class TemplatesImplStub {

        private byte[] _bytecodes;

        /**
         * setter：安全实现——当 SupportNonPublicField 未开启时拒绝写入不可信字节码。
         * 此处按实现判定为安全：不可信 _bytecodes 不会被注入。
         */
        public void set_bytecodes(byte[] bc, boolean supportNonPublicField) {
            if (!supportNonPublicField) {
                // 安全处理：未开启 SupportNonPublicField，拒绝写入私有危险字段
                System.out.println("[demo-only] SupportNonPublicField off: reject _bytecodes write");
                return;
            }
            this._bytecodes = bc;
        }

        /**
         * getter：由于 _bytecodes 始终为空（写入被拒），defineClass 无可操作载荷，
         * 危险语义不可达。
         */
        public Object getOutputProperties() {
            return defineClass(_bytecodes);
        }

        private Object defineClass(byte[] bytecodes) {
            if (bytecodes == null) {
                // 安全态：无不可信字节码，defineClass 不会加载恶意类
                System.out.println("[demo-only] defineClass safe: no attacker bytecodes");
                return new Object();
            }
            System.out.println("[demo-only] defineClass reached with attacker _bytecodes");
            return new Object();
        }
    }

    /**
     * 安全演示入口：未开启 SupportNonPublicField → defineClass 不可达。
     */
    // [CHECKPOINT id=JSEF-GM-007S cwe=502 level=L4 source=@type/_bytecodes sink=defineClass (SupportNonPublicField off) expect=SAFE]
    public static void safeDemo(boolean autoTypeSupport, boolean supportNonPublicField) {
        // 未开启 SupportNonPublicField（或字段只读校验）→ 不可达
        TemplatesImplStub stub = new TemplatesImplStub();
        stub.set_bytecodes(new byte[]{0x01}, supportNonPublicField);   // 安全态：写入被拒
        stub.getOutputProperties();
    }
}
