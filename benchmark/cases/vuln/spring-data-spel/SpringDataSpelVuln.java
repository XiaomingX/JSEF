package com.jsef.benchmark.vuln;

/*
 * JSEF-Benchmark L4 — Spring Data @Query 内 SpEL 注入
 *
 * 难度：L4（跨文件 / 框架语义）。@Query 注解中使用 ?#{#userInput} 的 SpEL
 * 表达式，把不可信 userInput 作为表达式的一部分求值，污点经注解 → Spring Data
 * 解析 → SpEL 求值跨框架层，纯语法 SAST 难以识别注解内 SpEL 的解析语义。
 *
 * CWE-917 (Expression Language Injection)。
 * 安全底线：仅 localhost 演示语义，不提供真实利用载荷。
 *
 * 修复要点（对照 SpringDataSpelSafe.java）：使用 ?1 参数化占位符并绑定参数。
 */
public class SpringDataSpel {

    // @Query 注解内 SpEL 引用外来源（trace 节点①）
    // [CHECKPOINT id=JSEF-NV510 cwe=917 level=L4 source=userInput sink=SpEL in @Query expect=VULN trace=benchmark/cases/vuln/spring-data-spel/SpringDataSpelVuln.java:20,benchmark/cases/vuln/spring-data-spel/SpringDataSpelVuln.java:26]
    // @Query("select u from User u where u.name = ?#{#userInput}")
    static final String QUERY = "select u from User u where u.name = ?#{#userInput}";

    /**
     * @param userInput 用户可控输入（进入 SpEL 求值）
     */
    public void run(String userInput) {
        parseExpression(QUERY.replace("#userInput", userInput));   // 解析点（trace 节点②）
    }

    // 抽象 sink：语义等价 SpelExpressionParser 按 @Query SpEL 求值
    static void parseExpression(String expr) {
        System.out.println("[spel-eval] " + expr);
    }

    public static void main(String[] args) {
        new SpringDataSpel().run("1') or 1=1 or ('1");
    }
}
