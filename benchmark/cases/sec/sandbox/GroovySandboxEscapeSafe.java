package com.jsef.benchmark.sec;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * JSEF-Benchmark L5 — 沙箱逃逸 安全对照（SAFE 对照）
 *
 * 安全做法（针对 CWE-265 Groovy 沙箱被绕过）：
 *  1) 完整 AST 黑名单：不仅拦截 {@code exec}/{@code Runtime}，还拦截所有反射入口
 *     （{@code getClass}/{@code forName}/{@code invoke} 等元编程跳板）。
 *  2) 严格类型限制：类型白名单之外的类一律禁止实例化/访问，元编程跳板无法取得。
 *  3) 运行时同样受限：符号表只暴露无害对象，无法作为反射起点。
 *
 * 这样编译期 AST 校验与运行时类型限制共同封锁逃逸路径，不应报（计入 TN / FP）。
 *
 * CWE-265 Privilege / Sandbox Issues（沙箱配置可被绕过语义）。
 */
public class GroovySandboxEscapeSafe {

    /** 完整 AST 黑名单：含反射入口，覆盖元编程跳板。 */
    private static final Set<String> AST_BLACKLIST = new HashSet<>(Arrays.asList(
            "exec", "Runtime", "getClass", "forName", "invoke", "getMethod", "reflect"));
    /** 严格类型白名单。 */
    private static final Set<String> TYPE_WHITELIST = new HashSet<>(Arrays.asList("String", "Integer", "List"));

    static class Scope {
        final java.util.Map<String, Object> vars = new java.util.HashMap<>();
        Object get(String k) { return vars.get(k); }
    }

    /**
     * 安全运行时求值：AST 黑名单 + 类型白名单双重封锁，无反射跳板。
     *
     * @param untrustedScript 不可信脚本
     */
    public static Object evalViaMetaProgrammingSafe(String untrustedScript) {
        Scope scope = new Scope();
        scope.set("pivot", "localhost-demo");

        // 完整 AST 黑名单：任何含反射/危险词的脚本在编译期即被拒绝
        for (String banned : AST_BLACKLIST) {
            if (untrustedScript.contains(banned)) {
                throw new SecurityException("AST blacklist blocked (no meta-programming escape)");
            }
        }

        // [CHECKPOINT id=JSEF-V2-002S cwe=265 level=L5 source=untrustedScript sink=Runtime.getRuntime().exec(meta-programming) expect=SAFE]
        return scope.get("pivot");  // 仅无害字符串，无反射 exec 路径
    }

    public static void main(String[] args) {
        evalViaMetaProgrammingSafe("def x = pivot; x");
    }
}
