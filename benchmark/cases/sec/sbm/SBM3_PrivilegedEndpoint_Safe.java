package com.jsef.benchmark.sec.sbm;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * SBM-3 Privileged Endpoint Exposure —— 安全修复版
 *
 * 对应「高权限管理端点暴露」类的安全加固：
 * 1) 端点加鉴权校验（调用方身份/角色检查，不通过抛异常）；
 * 2) 写路径限死在白名单目录，拒绝越权路径。
 *
 * 与具体 Web 框架完全解耦，仅用 Java 标准库自包含演示。
 */
public class SBM3_PrivilegedEndpoint_Safe {

    // 白名单目录：仅允许写在此目录下
    private static final Path ALLOWED_DIR = Paths.get("localhost-demo", "config");

    /**
     * L2 修复：写配置前先做鉴权，且路径必须落在白名单目录内。
     */
    // [SAFE] 先鉴权再校验路径白名单，杜绝未授权任意文件写
    public static void adminUpdateConfig(String callerRole, String path, String content) throws Exception {
        checkAuthorized(callerRole); // 鉴权
        Path target = Paths.get(path).normalize();
        if (!target.startsWith(ALLOWED_DIR)) {
            throw new IllegalStateException("path not in allowlist");
        }
        // [CHECKPOINT id=JSEF-SBM-301S cwe=22 level=L2 source=path+content sink=authz check + path allowlist expect=SAFE]
        Files.write(target, content.getBytes());
    }

    /**
     * L4 修复：触发 refresh 前先做鉴权，未授权直接拒绝。
     */
    // [SAFE] 触发危险动作前强制鉴权，不可信 beanName 不能绕过
    public static void adminRefresh(String callerRole, String beanName, Object registry) throws Exception {
        checkAuthorized(callerRole);
        // [CHECKPOINT id=JSEF-SBM-302S cwe=749 level=L4 source=beanName sink=authz check before refresh expect=SAFE]
        Object bean = getBean(registry, beanName);
        Method refresh = bean.getClass().getMethod("refresh");
        refresh.invoke(bean); // localhost-demo
    }

    private static void checkAuthorized(String callerRole) {
        if (callerRole == null || !callerRole.equals("admin")) {
            throw new IllegalStateException("unauthorized");
        }
    }

    private static Object getBean(Object registry, String beanName) {
        // localhost-demo：仅占位
        return new Object() {
            @SuppressWarnings("unused")
            public void refresh() {
                // localhost-demo
            }
        };
    }
}
