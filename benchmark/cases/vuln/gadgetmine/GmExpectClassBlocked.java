package com.jsef.benchmark.vuln.gadgetmine;

/**
 * JSEF-Benchmark gadgetmine 族 — 验收维度 §一 (3)：1.2.68+ 后置接口封堵
 * ============================================================
 * 验收目标：被测工具能否判定 1.2.68+ 后置 expectClass 接口的封堵效果。
 *
 * 本题结论（应为 SAFE）：
 *   在 fastjson 1.2.68+ 的 `expectClass` 入口中，loadClass 成功后若目标类
 *   是以下任一接口的实现/子类，直接抛错拒绝：
 *     - java.lang.ClassLoader
 *     - javax.sql.DataSource
 *     - javax.sql.RowSet
 *   因此经典 JdbcRowSetImpl（实现 RowSet）直连链在 1.2.68+ 起被封堵，
 *   不再构成可达 gadget，应判 SAFE。
 *
 * 安全底线声明：仅 localhost 演示语义。本文件不 import 真实 fastjson，
 *   不提供真实利用脚本；`RowSetGadgetStub` 为占位类，仅表达"接口封堵"
 *   的 gadget 判定语义。
 */
public class GmExpectClassBlocked {

    /**
     * 教学占位 gadget 类：模拟实现 javax.sql.RowSet 的类（如 JdbcRowSetImpl）。
     * 不 import 真实 fastjson；仅以注释表达其语义等价关系。
     */
    // 语义等价：javax.sql.RowSet 实现类（如 JdbcRowSetImpl），fastjson 1.2.68+ 下经 expectClass 入口会被封堵。
    public static class RowSetGadgetStub {
        // 占位：模拟 RowSet 实现类的危险字段（dataSourceName / autoCommit）
    }

    /**
     * 模拟 1.2.68+ expectClass 解析路径：loadClass 后做接口判定。
     */
    public static Object resolveViaExpectClass(String typeName) {
        Class<?> clazz = loadClass(typeName);   // 加载目标类

        // [CHECKPOINT id=JSEF-GM-006 cwe=502 level=L4 source=@type sink=expectClass interface block (1.2.68+) expect=SAFE trace=benchmark/cases/vuln/gadgetmine/GmExpectClassBlocked.java:39,benchmark/cases/vuln/gadgetmine/GmExpectClassBlocked.java:43]
        if (isBlockedInterface(clazz)) {   // 接口判定行：ClassLoader/DataSource/RowSet -> 封堵
            throw new UnsupportedOperationException(
                    "expectClass block: " + typeName + " implements blocked interface (1.2.68+)");
        }
        return instantiate(clazz);   // 抛错行：blocked 类不会到达此处
    }

    /** 模拟 loadClass。 */
    private static Class<?> loadClass(String typeName) {
        System.out.println("[demo-only] loadClass: " + typeName);
        return RowSetGadgetStub.class;  // 占位：假定加载到 RowSet 实现类
    }

    /** 模拟 1.2.68+ 后置接口封堵判定。 */
    private static boolean isBlockedInterface(Class<?> clazz) {
        // 占位判定：实际 fastjson 检查 ClassLoader / DataSource / RowSet
        return true;  // 演示：RowSet 实现类被封堵
    }

    /** 模拟实例化（封堵后不会到达）。 */
    private static Object instantiate(Class<?> clazz) {
        System.out.println("[demo-only] instantiate blocked type (unreachable): " + clazz);
        return null;
    }
}
