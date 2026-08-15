package com.jsef.benchmark.vuln.tcm;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * TCM-5 属性即代码（Property As Code / 隐式方法危险）
 * ====================================================
 * 核心范式 P0 的变体：攻击者控制类型/数据 + 系统在「构造期 / 属性访问期」
 * 自动调用隐式方法（getter / setter / close）+ 隐式方法链路抵达危险 sink。
 *
 * 对应 某JSON反序列化库 Tips / JNDI 经 setter / getter 触发的经典链路：
 *   反序列化过程中，某JSON反序列化库 会自动调用 setter 注入字段、调用 getter 惰性
 *   取值；若 POJO 的 getter/setter 非幂等且含有危险副作用（JNDI lookup、
 *   DNS/SSRF 解析），则「属性访问」即「代码执行」。本样本把这一机制抽象为
 *   纯 Java 标准库（javax.naming.Context / java.net.InetAddress）自包含复现，
 *   不引入任何具体 JSON/序列化库。
 *
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串，
 * 不连真实远端、不写真实利用脚本。
 */
public class TCM5_PropertyAsCode {

    /**
     * L1：getter 非幂等且危险——getConfig() 内部直接做 JNDI lookup / 网络解析，
     * host/url 来自私有字段（由 setter 接收不可信输入写入）。
     */
    public static class L1Target {
        @SuppressWarnings("unused")
        private String url; // 由 setter 接收不可信输入

        public void setUrl(String url) { // setter：接收不可信输入
            this.url = url;
        }

        public Object getConfig() throws NamingException, UnknownHostException {
            // [VULN] getter 非幂等：内部触发 JNDI lookup（属性即代码）
            Context ctx = new InitialContext();
            // [CHECKPOINT id=JSEF-TCM-501 cwe=502 level=L1 source=field(url) sink=JNDI.lookup(url)/InetAddress.getByName expect=VULN]
            return ctx.lookup(url); // 仅占位 "localhost-demo"，不连真实远端
        }
    }

    /**
     * L3：setter 内部直接危险——setDataSource(String url) 在 setter 体内
     * 直接执行 ctx.lookup(url)，url 不可信。跨节点：入口 setter -> lookup。
     */
    public static class L3Target {
        @SuppressWarnings("unused")
        private Object dataSource;

        public void setDataSource(String url) throws NamingException { // 行：setter 入口
            Context ctx = new InitialContext();
            // [VULN] setter 非幂等：在 setter 体内直接执行 JNDI lookup
            // [CHECKPOINT id=JSEF-TCM-502 cwe=502 level=L3 source=setter url sink=Context.lookup(url) expect=VULN trace=benchmark/cases/vuln/tcm/TCM5_PropertyAsCode.java:55,benchmark/cases/vuln/tcm/TCM5_PropertyAsCode.java:59]
            dataSource = ctx.lookup(url); // 行：lookup 调用，仅占位 "localhost-demo"
        }
    }

    /**
     * L5：跨方法链——resolve() 经 getter 链（getter 调 getter）最终抵达
     * JNDI lookup。对应 某JSON反序列化库 Tips：getter 链式触发，末节点做 JNDI 注入。
     * 节点：url 字段设置入口 -> 中间 getter getJndiUrl -> 末 getter lookup。
     */
    public static class L5Target {
        @SuppressWarnings("unused")
        private String url; // 行：url 字段（入口，由外部设置）

        public void setUrl(String url) { // 行：入口 setter，外部不可信输入写入 url
            this.url = url;
        }

        public String getJndiUrl() { // 行：中间 getter
            return "ldap://localhost-demo/" + url; // 仅占位，不连真实远端
        }

        public Object resolve() throws NamingException {
            // getter 链：resolve -> getJndiUrl 构造目标 -> 末节点 lookup
            String target = getJndiUrl(); // 中间节点：getter 链
            Context ctx = new InitialContext();
            // [VULN] 跨方法 getter 链末节点触发 JNDI lookup
            // [CHECKPOINT id=JSEF-TCM-503 cwe=502 level=L5 source=field(url) sink=ctx.lookup(url) via getter-chain expect=VULN trace=benchmark/cases/vuln/tcm/TCM5_PropertyAsCode.java:72,benchmark/cases/vuln/tcm/TCM5_PropertyAsCode.java:76,benchmark/cases/vuln/tcm/TCM5_PropertyAsCode.java:86]
            return ctx.lookup(target); // 行：lookup 调用，仅占位 "localhost-demo"
        }
    }

    /**
     * L1 演示入口：setter 注入不可信 url，随后 getter 访问即触发 JNDI。
     */
    public void demoL1() throws Exception {
        L1Target t = new L1Target();
        t.setUrl("ldap://localhost-demo/evil"); // 不可信输入
        t.getConfig(); // 属性访问 = 代码执行
    }

    /**
     * L3 演示入口：setter 注入不可信 url，setter 体内即触发 JNDI。
     */
    public void demoL3() throws Exception {
        L3Target t = new L3Target();
        t.setDataSource("ldap://localhost-demo/evil"); // setter 体内直接 lookup
    }

    /**
     * L5 演示入口：setter 注入不可信 url，resolve() 经 getter 链触发 JNDI。
     */
    public void demoL5() throws Exception {
        L5Target t = new L5Target();
        t.setUrl("localhost-demo"); // 入口：不可信输入写入 url 字段
        t.resolve(); // getter 链 -> JNDI lookup
    }
}
