package com.jsef.benchmark.sec.tcm;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.util.Arrays;
import java.util.List;

/**
 * TCM-5 修复（Property As Code — Safe）
 * ====================================
 * 修复点（对应 某JSON反序列化库 Tips / JNDI 经 setter/getter 触发）：
 *   1) getter / setter 保持无副作用、幂等：绝不内部执行 JNDI lookup 或网络
 *      解析；危险操作从隐式方法（属性访问）移到显式、受控的服务端调用。
 *   2) 任何 JNDI / 网络目标 URL 必须经白名单（allowlist）校验：仅允许
 *      localhost 或固定安全前缀，拒绝 ldap:// / rmi:// 等不可信协议。
 *
 * 仅 localhost 演示语义，所有危险占位调用使用 "localhost-demo" 字符串。
 */
public class TCM5_PropertyAsCode_Safe {

    // URL 白名单：仅允许 localhost 安全前缀，拒绝 ldap:// rmi:// 等协议
    private static final List<String> ALLOWED_PREFIXES =
            Arrays.asList("localhost-demo", "file:///safe/", "http://localhost/");

    private static boolean isAllowed(String url) {
        if (url == null) return false;
        return ALLOWED_PREFIXES.stream().anyMatch(url::startsWith);
    }

    /**
     * L1 修复：getter 无副作用，仅返回已校验的本地配置；危险 JNDI 调用被移除。
     */
    public static class L1Target {
        @SuppressWarnings("unused")
        private String url;

        public void setUrl(String url) {
            // [SAFE] setter 不做危险副作用，仅保存经白名单校验的输入
            if (!isAllowed(url)) {
                throw new IllegalArgumentException("url not in allowlist: " + url);
            }
            this.url = url;
        }

        public Object getConfig() throws NamingException {
            // [SAFE] getter 幂等：不触发任何隐式危险方法
            // [CHECKPOINT id=JSEF-TCM-501S cwe=502 level=L1 source=field(url) sink=whitelist-checked lookup expect=SAFE]
            return "config:" + url; // 不执行 JNDI lookup
        }
    }

    /**
     * L3 修复：setter 不直接执行 lookup；URL 经 allowlist 校验后才允许使用。
     */
    public static class L3Target {
        @SuppressWarnings("unused")
        private Object dataSource;

        public void setDataSource(String url) throws NamingException {
            // [SAFE] setter 不做危险副作用，先做 URL allowlist 校验
            // [CHECKPOINT id=JSEF-TCM-502S cwe=502 level=L3 source=setter url sink=url allowlist check expect=SAFE]
            if (!isAllowed(url)) {
                throw new IllegalArgumentException("url not in allowlist: " + url);
            }
            Context ctx = new InitialContext();
            this.dataSource = ctx.lookup(url); // 仅 "localhost-demo" 占位，allowlist 后
        }
    }

    /**
     * L5 修复：getter 链无副作用，resolve() 不隐式触发 JNDI；
     * 危险 lookup 被显式、allowlist 保护的调用替代。
     */
    public static class L5Target {
        @SuppressWarnings("unused")
        private String url;

        public void setUrl(String url) {
            // [SAFE] 入口即校验，拒绝不可信 url
            if (!isAllowed(url)) {
                throw new IllegalArgumentException("url not in allowlist: " + url);
            }
            this.url = url;
        }

        public String getJndiUrl() {
            return "localhost-demo/" + url; // 幂等，无危险调用
        }

        public Object resolve() throws NamingException {
            // [SAFE] getter 链无副作用，不隐式触发 JNDI
            // [CHECKPOINT id=JSEF-TCM-503S cwe=502 level=L5 source=field(url) sink=no side-effect getter expect=SAFE]
            String target = getJndiUrl();
            Context ctx = new InitialContext();
            return ctx.lookup(target); // 仅 "localhost-demo" 占位，allowlist 已前置
        }
    }

    public void demoL1() throws Exception {
        L1Target t = new L1Target();
        t.setUrl("localhost-demo"); // allowlist 校验通过
        t.getConfig();
    }

    public void demoL3() throws Exception {
        L3Target t = new L3Target();
        t.setDataSource("localhost-demo"); // allowlist 校验后
    }

    public void demoL5() throws Exception {
        L5Target t = new L5Target();
        t.setUrl("localhost-demo");
        t.resolve(); // 显式、allowlist 保护
    }
}
