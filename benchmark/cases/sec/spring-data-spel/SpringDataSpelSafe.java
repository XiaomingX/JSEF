package com.jsef.benchmark.sec;

/*
 * JSEF-Benchmark L4 — Spring Data @Query 安全对照
 *
 * 修复：使用 ?1 参数化占位符，userInput 仅作绑定参数，不进入 SpEL。
 * SAFE 侧按实现判定安全。
 */
public class SpringDataSpelSafe {

    // 参数化查询，无 SpEL
    // @Query("select u from User u where u.name = ?1")
    static final String QUERY = "select u from User u where u.name = ?1";

    public void run(String userInput) {
        // [CHECKPOINT id=JSEF-NV510S cwe=917 level=L4 source=userInput sink=SpEL in @Query expect=SAFE]
        bindParam(QUERY, userInput);   // 参数化绑定
    }

    static void bindParam(String q, String param) {
        System.out.println("[query-param] " + q + " <- " + param);
    }

    public static void main(String[] args) {
        new SpringDataSpelSafe().run("alice");
    }
}
