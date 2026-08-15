package com.jsef.benchmark.vuln.sbm;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * SBM-3 Privileged Endpoint Exposure（特权端点暴露）
 *
 * 对应「高权限管理端点暴露」类：env / refresh 等高权限管理端点未鉴权，
 * 直接接受不可信写操作（写文件 / 触发 bean 危险刷新），造成任意文件写与
 * 危险动作触发。本文件与具体 Web 框架完全解耦，用 Java 标准库自包含演示。
 *
 * 维度：框架机制 SBM（框架机制原子范式） —— 端点暴露。
 * 仅 localhost 演示语义，危险调用以 "localhost-demo" 占位。
 */
public class SBM3_PrivilegedEndpoint {

    /**
     * L2：管理端点未鉴权，直接把不可信 path+content 写入文件系统。
     */
    // [VULN] 高权限写端点无鉴权，攻击者可控 path/content 触发任意文件写
    public static void adminUpdateConfig(String path, String content) throws Exception {
        // [CHECKPOINT id=JSEF-SBM-301 cwe=22 level=L2 source=untrusted path+content (no authz) sink=Files.write(path, content) expect=VULN]
        Files.write(Paths.get(path), content.getBytes());
    }

    /**
     * L4：管理端点接受不可信 beanName，通过 Method.invoke 触发名为 refresh 的
     * 危险动作（对应高权限 refresh 端点未鉴权触发全局刷新）。
     * trace 节点：行1 = beanName 入口；行2 = invoke refresh。
     */
    // [VULN] 端点接受不可信 beanName 且无鉴权，可触发任意 bean 的 refresh 危险动作
    public static void adminRefresh(String beanName, Object registry) throws Exception {
        Object bean = getBean(registry, beanName); // 行1：beanName 入口（不可信）
        Method refresh = bean.getClass().getMethod("refresh");
        // [CHECKPOINT id=JSEF-SBM-302 cwe=749 level=L4 source=untrusted beanName (no authz) sink=Method.invoke(refresh) expect=VULN trace=benchmark/cases/vuln/sbm/SBM3_PrivilegedEndpoint.java:35,benchmark/cases/vuln/sbm/SBM3_PrivilegedEndpoint.java:38]
        refresh.invoke(bean); // 行2：invoke refresh 危险动作（localhost-demo）
    }

    // 抽象 bean 查找（模拟通用容器 getBean）
    private static Object getBean(Object registry, String beanName) {
        // localhost-demo：仅占位，不接真实容器
        return new Object() {
            @SuppressWarnings("unused")
            public void refresh() {
                // localhost-demo: 触发危险刷新动作（仅演示语义）
            }
        };
    }
}
