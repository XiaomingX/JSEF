// [VULN]
package com.jsef.benchmark.vuln.sbm;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.util.ArrayList;
import java.util.List;

/**
 * JSEF-Benchmark — SBM-2 Config-as-Expression (A03 注入/表达式求值, L2 & L4)
 *
 * 抽象范式（与具体网关/路由框架完全解耦）：声明式配置（路由定义、规则定义）
 * 被持久化/存储后，由求值引擎在后续阶段执行。当配置内容来自不可信输入且
 * 存储后未经净化即被 eval，攻击者控制配置即可实现「存储型 eval = 代码执行」。
 *
 * 区别于 L0「直输即 eval」：此处强调「配置存储后再被求值」的跨阶段语义——
 * 求值引擎消费的是已落库的声明式配置，而非当次请求直传的表达式。
 *
 * 对应「网关配置求值注入」（配置存储后由求值引擎执行）的危险机制，但此处仅
 * 用标准库 javax.script.ScriptEngine 自包含演示，绝不使用任何具体 Web 框架
 * 类名，不与任何具体框架绑定。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不写真实利用脚本、不连真实远端。
 */
public class SBM2_ConfigExpression {

    // 模拟配置存储（声明式路由/规则定义库）
    private static final List<String> routeStore = new ArrayList<>();

    /**
     * L2：route 定义来自不可信输入，存入配置库；evalRoute 用 ScriptEngine
     * 对存储的定义求值。定义中的表达式在存储后由引擎执行。
     */
    public static void addRoute(String definition) {
        routeStore.add(definition); // 定义存入配置库（不可信来源）
    }

    public static void evalRoute() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        for (String def : routeStore) {
            // [CHECKPOINT id=JSEF-SBM-201 cwe=917 level=L2 source=stored route definition sink=ScriptEngine.eval(definition) expect=VULN]
            engine.eval(def);
        }
    }

    /**
     * L4：跨阶段示例。存储阶段 addRouteDef 将定义持久化；求值阶段由独立入口
     * evalStoredRoutes 触发 ScriptEngine 求值，体现「配置存储后被求值」跨阶段。
     */
    public static void addRouteDef(String def) {
        routeStore.add(def); // 存储阶段：定义持久化（跨阶段起点）
    }

    public static void evalStoredRoutes() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        for (String def : routeStore) {
            // [CHECKPOINT id=JSEF-SBM-202 cwe=917 level=L4 source=stored config (cross-stage) sink=ScriptEngine.eval expect=VULN trace=benchmark/cases/vuln/sbm/SBM2_ConfigExpression.java:51,benchmark/cases/vuln/sbm/SBM2_ConfigExpression.java:58]
            engine.eval(def);
        }
    }

    // 演示入口（仅 localhost 语义，不连真实远端）
    public static void main(String[] args) throws Exception {
        // 不可信 POST 内容（localhost 演示占位）
        addRoute("java.lang.Runtime"); // 占位，非真实利用
        evalRoute();
        addRouteDef("localhost-demo"); // 占位，非真实利用
        evalStoredRoutes();
    }
}
