// [VULN]
package com.jsef.benchmark.vuln.sbm;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * JSEF-Benchmark — SBM-1 Binder Traversal (A03 注入/数据绑定, L3 & L5)
 *
 * 抽象范式（与具体 Web 框架完全解耦）：通用「属性绑定器」按字符串路径
 * ("a.b.c") 自动穿越调用嵌套对象的 getter/setter。当路径穿越到内部危险对象
 * (类比 class.module.classLoader 穿越) 且其危险属性被写时，攻击者即可借由
 * 受控路径改变内部状态。
 *
 * 对应「类加载器穿越」危险机制（类名.模块.类加载器 路径穿越），但此处仅用
 * java.lang.reflect 标准库自包含演示，绝不使用任何具体 Web 框架类名，
 * 不与任何具体框架绑定。
 *
 * 安全底线：Payload 仅 localhost 演示语义，危险调用用 "localhost-demo" 占位，
 * 不写真实 RCE 利用脚本、不连真实远端。
 */
public class SBM1_BinderTraversal {

    /**
     * 嵌套数据对象，模拟可被穿越绑定的目标。
     */
    public static class Inner {
        private String logPath = "localhost-demo/app.log";
        public String getLogPath() { return logPath; }
        public void setLogPath(String logPath) { this.logPath = logPath; }
    }

    public static class Middle {
        private Inner inner = new Inner();
        public Inner getInner() { return inner; }
        public void setInner(Inner inner) { this.inner = inner; }
    }

    public static class Root {
        private Middle middle = new Middle();
        public Middle getMiddle() { return middle; }
        public void setMiddle(Middle middle) { this.middle = middle; }
    }

    /**
     * L3：通用属性绑定器。按 "a.b.c" 路径用反射穿越调用嵌套 getter/setter。
     * 污点 path 含 class.module.classLoader 风格穿越时，会被解析到内部
     * 危险对象并调用其 setXxx 写危险属性。
     */
    public static void bind(Object root, String path, String value)
            throws Exception {
        String[] parts = path.split("\\.");
        Object current = root;
        for (int i = 0; i < parts.length - 1; i++) { // path 解析穿越起点
            Method getter = current.getClass().getMethod("get" + capitalize(parts[i]));
            current = getter.invoke(current);
        }
        String last = parts[parts.length - 1];
        Method setter = current.getClass().getMethod("set" + capitalize(last), String.class);
        // [CHECKPOINT id=JSEF-SBM-101 cwe=94 level=L3 source=path string (a.b.c traversal) sink=reflection setXxx on internal object expect=VULN trace=benchmark/cases/vuln/sbm/SBM1_BinderTraversal.java:55,benchmark/cases/vuln/sbm/SBM1_BinderTraversal.java:62]
        setter.invoke(current, value);
    }

    /**
     * L5：绑定穿越到内部对象后，最终触发文件写 (抽象为日志路径篡改 -> 文件写)。
     * 路径穿越写内部 Inner.logPath 后，随后用该字段作为路径 Files.write。
     */
    public static void bindChain(Object root, String path, String value)
            throws Exception {
        // 先穿越绑定，污染内部危险属性
        bind(root, path, value);
        // 取回内部对象的危险字段，作为文件写路径
        Root r = (Root) root;
        String target = r.getMiddle().getInner().getLogPath();
        // [CHECKPOINT id=JSEF-SBM-102 cwe=94 level=L5 source=path traversal sink=Files.write(internal object field) expect=VULN trace=benchmark/cases/vuln/sbm/SBM1_BinderTraversal.java:55,benchmark/cases/vuln/sbm/SBM1_BinderTraversal.java:62,benchmark/cases/vuln/sbm/SBM1_BinderTraversal.java:77]
        Files.write(Paths.get("localhost-demo/" + target), "localhost-demo".getBytes());
    }

    private static String capitalize(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    // 演示入口（仅 localhost 语义，不连真实远端）
    public static void main(String[] args) throws Exception {
        Root root = new Root();
        // 类比 class.module.classLoader 穿越：middle.inner.logPath
        bind(root, "middle.inner.logPath", "localhost-demo/pwned.log");
        bindChain(root, "middle.inner.logPath", "localhost-demo/pwned.log");
    }
}
