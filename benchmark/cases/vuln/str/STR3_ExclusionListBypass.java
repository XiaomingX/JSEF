/*
 * JSEF Benchmark 样本 — STR-3 Eval Exclusion-list Bypass by Context Switch（CWE-917，表达式沙箱/排除列表绕过）
 *
 * 维度抽象：从「表达式引擎排除列表（黑名单类/方法）被上下文切换 + 串联子表达式绕过」这一类
 * 历史漏洞中抽象出的「表达式机制 STR」原子范式，与任何具体 Web 框架完全解耦。
 * 本文件仅用 Java 标准库自包含模拟：自建 EvalEngine 内部维护排除列表
 * Set<String> excluded（如 "Runtime"/"exec"），eval(String expr) 先检查 expr 是否含被禁 token，
 * 若含则拒绝；但攻击者用「表达式内上下文切换」（模拟访问权限上下文改访问权限，或
 * (expr1).(expr2) 串联）绕过该字符串级排除检查，最终用 Method.invoke 调用 Runtime.exec。
 *
 * 对应历史「表达式沙箱绕过」类漏洞（排除列表被上下文切换 + 串联绕过）：排除列表是字符串级匹配，
 * 上下文切换 + 子表达式串联让被禁 token 不在顶层字面量出现，从而绕过检查并恢复运行时调用能力。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本，不连真实远端。
 * 危险调用以 "localhost-demo" 占位。
 *
 * 本文件不出现任何具体表达式框架类名或包，纯标准库自包含。
 */

package com.jsef.benchmark.vuln.str;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

public class STR3_ExclusionListBypass {

    // ------------------------------------------------------------------
    // EvalEngine：表达式引擎抽象（标准库自包含，不含任何具体框架引用）
    //  - excluded：字符串级排除列表（黑名单），命中即拒绝。
    //  - 攻击者通过「表达式内上下文切换 + 串联子表达式」绕过该字符串级检查。
    // ------------------------------------------------------------------
    static class EvalEngine {
        // 排除列表（字符串级黑名单）：含这些 token 的表达式被拒绝
        final Set<String> excluded = new HashSet<>();

        EvalEngine() {
            excluded.add("Runtime");   // 禁止直接出现 Runtime 类字面量
            excluded.add("exec");      // 禁止直接出现 exec 方法名字面量
        }

        // 字符串级排除检查：仅对顶层 expr 字面量做 token 包含判断（可被上下文切换绕过）
        boolean blockedByExclusion(String expr) {
            for (String token : excluded) {
                if (expr.contains(token)) {
                    return true;       // 命中黑名单 => 拒绝
                }
            }
            return false;
        }

        // 模拟上下文切换：表达式内 (getContext().setAccess(true)) 改访问权限
        // 真实漏洞对应访问权限上下文被提升，使被禁调用可被解析。
        boolean getContextAccess() {
            return true;               // 上下文切换后访问权限被打开
        }

        // 危险调用封装：通过 Method.invoke 调用 Runtime.exec（localhost-demo 占位）
        Object invokeRuntime() throws Exception {
            Method exec = Runtime.class.getMethod("exec", String.class);
            // [VULN] 通过反射 Method.invoke 恢复被禁的运行时调用（排除列表已被绕过）
            return exec.invoke(Runtime.getRuntime(), "localhost-demo");
        }
    }

    // ------------------------------------------------------------------
    // L3 维度：eval(String expr) — 排除列表被「表达式内上下文切换 + 串联」绕过
    // 攻击者构造 (getContext().setAccess(true)).(invokeRuntime()) 风格串联子表达式：
    // 顶层字面量不含 "Runtime"/"exec"，字符串级排除检查被绕过；上下文切换打开权限后
    // 串联的 invokeRuntime() 恢复被禁的运行时调用。
    // ------------------------------------------------------------------

    // [VULN] 排除列表仅做字符串级检查，无法防御表达式内上下文切换 + 串联绕过
    static Object eval(String expr) throws Exception {
        EvalEngine engine = new EvalEngine();

        // [VULN] 排除检查被绕过点：顶层 expr 字面量不含被禁 token，检查通过（行1）
        if (engine.blockedByExclusion(expr)) {
            return "localhost-demo: rejected by exclusion";
        }

        // [VULN] 上下文切换：模拟 #_memberAccess 改访问权限，使被禁调用可被解析（行2）
        boolean access = engine.getContextAccess();   // 上下文切换打开访问权限

        // [VULN] 串联子表达式：invokeRuntime() 在被打开权限的上下文中恢复被禁调用
        if (access) {
            // [CHECKPOINT id=JSEF-STR-301 cwe=917 level=L3 source=expression with context-switch sink=invoker->Runtime.exec (exclusion bypass) expect=VULN trace=benchmark/cases/vuln/str/STR3_ExclusionListBypass.java:78,benchmark/cases/vuln/str/STR3_ExclusionListBypass.java:83,benchmark/cases/vuln/str/STR3_ExclusionListBypass.java:88]
            return engine.invokeRuntime();            // 串联调用恢复 Runtime.exec（行exec）
        }
        return "localhost-demo: no access";
    }

    // ------------------------------------------------------------------
    // L4 维度：evalEvasive(String expr) — 排除列表精确匹配方法名 "exec"，
    // 攻击者用表达式内反射字符串拼接变形 ("ex"+"ec") + 上下文切换调用被禁方法。
    // 排除检查匹配顶层字面量 "exec" 失败（被拆成拼接），反射变形后 invoke 被禁方法。
    // ------------------------------------------------------------------

    // [VULN] 排除列表精确匹配方法名，被反射字符串拼接变形 + 上下文切换绕过
    static Object evalEvasive(String expr) throws Exception {
        EvalEngine engine = new EvalEngine();

        // [VULN] 排除检查被绕过点：expr 中 "exec" 被拆为 "ex"+"ec" 拼接，字面量未命中（行1）
        if (engine.blockedByExclusion(expr)) {
            return "localhost-demo: rejected by exclusion";
        }

        // [VULN] 上下文切换 + 反射变形调用：getClass().getMethod("ex"+"ec", ...) 拼接变形（行2）
        String bannedName = "ex" + "ec";             // 字符串拼接变形，避开字面量 "exec"
        Method m = Runtime.class.getMethod(bannedName, String.class);

        // [VULN] 反射 invoke 被禁方法，排除列表已被绕过
        // [CHECKPOINT id=JSEF-STR-302 cwe=917 level=L4 source=expression with reflection-evasion sink=Method.invoke(banned method) expect=VULN trace=benchmark/cases/vuln/str/STR3_ExclusionListBypass.java:104,benchmark/cases/vuln/str/STR3_ExclusionListBypass.java:109]
        return m.invoke(Runtime.getRuntime(), "localhost-demo");
    }
}
