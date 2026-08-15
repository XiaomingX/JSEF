// [SAFE]
package com.jsef.benchmark.sec.sbm;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * JSEF-Benchmark — SBM-1 Binder Traversal 修复版 (A03 注入/数据绑定, L3 & L5)
 *
 * 与 SBM1_BinderTraversal 对应，但绑定器维护 disallowedPrefixes 黑名单
 * (class / module / classLoader 前缀)，拒绝穿越到内部危险对象，从而阻断
 * 借由字符串路径改变内部危险状态。纯标准库自包含，不出现任何具体框架类名。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不写真实利用脚本、不连真实远端。
 */
public class SBM1_BinderTraversal_Safe {

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

    // 黑名单：拦截 class / module / classLoader 等危险穿越前缀
    private static final List<String> DISALLOWED_PREFIXES =
            Arrays.asList("class", "module", "classLoader");

    private static boolean isDisallowed(String path) {
        for (String prefix : DISALLOWED_PREFIXES) {
            if (path.startsWith(prefix + ".")
                    || path.contains("." + prefix + ".")
                    || path.equals(prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * L3 修复：绑定前检查路径前缀，命中黑名单则拒绝穿越。
     */
    public static void bind(Object root, String path, String value)
            throws Exception {
        String[] parts = path.split("\\.");
        Object current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            Method getter = current.getClass().getMethod("get" + capitalize(parts[i]));
            current = getter.invoke(current);
        }
        // [CHECKPOINT id=JSEF-SBM-101S cwe=94 level=L3 source=path string sink=disallowed-prefix reject expect=SAFE]
        if (isDisallowed(path)) {
            throw new SecurityException("rejected binder traversal to internal object: " + path);
        }
        String last = parts[parts.length - 1];
        Method setter = current.getClass().getMethod("set" + capitalize(last), String.class);
        setter.invoke(current, value);
    }

    /**
     * L5 修复：穿越被黑名单阻断，内部危险字段永不被污染，因此不会触发文件写。
     */
    public static void bindChain(Object root, String path, String value)
            throws Exception {
        bind(root, path, value);
        Root r = (Root) root;
        String target = r.getMiddle().getInner().getLogPath();
        // [CHECKPOINT id=JSEF-SBM-102S cwe=94 level=L5 source=path traversal sink=no internal write expect=SAFE]
        if (isDisallowed(path)) {
            // 路径被拒绝，内部字段未污染，不执行任何文件写
            return;
        }
        Files.write(Paths.get("localhost-demo/" + target), "localhost-demo".getBytes());
    }

    private static String capitalize(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    // 演示入口（仅 localhost 语义，不连真实远端）
    public static void main(String[] args) throws Exception {
        Root root = new Root();
        try {
            bind(root, "middle.inner.logPath", "localhost-demo/pwned.log");
        } catch (SecurityException e) {
            // 期望：穿越被拒绝
        }
        try {
            bindChain(root, "middle.inner.logPath", "localhost-demo/pwned.log");
        } catch (SecurityException e) {
            // 期望：穿越被拒绝
        }
    }
}
