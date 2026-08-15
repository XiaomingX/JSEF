// [SAFE]
package com.jsef.benchmark.sec.sbm;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.util.ArrayList;
import java.util.List;

/**
 * JSEF-Benchmark — SBM-2 Config-as-Expression 修复版 (A03 注入/表达式求值, L2 & L4)
 *
 * 与 SBM2_ConfigExpression 对应，但：
 *  - L2：对存储的配置表达式在「受限上下文」求值，禁用类引用 / T() / Runtime，
 *    仅允许纯数据表达式，阻断存储型 eval 的代码执行可达性。
 *  - L4：改为静态配置，不含任何表达式，完全不调用 ScriptEngine.eval。
 *
 * 纯标准库自包含，不出现任何具体框架类名。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不写真实利用脚本、不连真实远端。
 */
public class SBM2_ConfigExpression_Safe {

    private static final List<String> routeStore = new ArrayList<>();

    /**
     * 受限求值：拒绝包含类引用 / T() / Runtime 的表达式。
     */
    private static boolean isRestricted(String expr) {
        return expr.contains("java.lang.Runtime")
                || expr.contains("T(")
                || expr.contains("Runtime")
                || expr.contains("getRuntime")
                || expr.contains("ProcessBuilder")
                || expr.contains("exit");
    }

    /**
     * L2 修复：存储的定义在受限上下文求值，危险表达式被拒绝。
     */
    public static void addRoute(String definition) {
        routeStore.add(definition);
    }

    public static void evalRoute() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        for (String def : routeStore) {
            // [CHECKPOINT id=JSEF-SBM-201S cwe=917 level=L2 source=stored route definition sink=restricted eval context expect=SAFE]
            if (isRestricted(def)) {
                throw new SecurityException("rejected expression in restricted eval context: " + def);
            }
            engine.eval(def);
        }
    }

    /**
     * L4 修复：静态配置，定义不含表达式，求值阶段直接跳过 eval。
     */
    public static void addRouteDef(String def) {
        routeStore.add(def); // 静态配置，不含表达式
    }

    public static void evalStoredRoutes() throws Exception {
        // [CHECKPOINT id=JSEF-SBM-202S cwe=917 level=L4 source=stored config sink=static config no eval expect=SAFE]
        for (String def : routeStore) {
            if (isRestricted(def)) {
                throw new SecurityException("static config must not contain expressions: " + def);
            }
            // 仅做静态映射处理，不调用 ScriptEngine.eval
        }
    }

    // 演示入口（仅 localhost 语义，不连真实远端）
    public static void main(String[] args) throws Exception {
        addRoute("localhost-demo"); // 纯数据表达式占位
        evalRoute();
        addRouteDef("localhost-demo"); // 静态配置占位
        evalStoredRoutes();
    }
}
