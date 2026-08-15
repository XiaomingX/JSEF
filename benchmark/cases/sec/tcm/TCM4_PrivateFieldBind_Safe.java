package com.jsef.benchmark.sec.tcm;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * TCM-4 修复（Private Field Bind — Safe）
 * ========================================
 * 修复点：
 *   1) L2：字段绑定走白名单（只允许安全字段），危险字段（command）被排除 /
 *      设为 final 只读，bindField 拒绝任何白名单外的私有字段写入。
 *   2) L4：不允许从外部动态绑定 ScriptEngine 引用；引擎由服务端固定构造，
 *      不暴露可写的私有引擎字段，惰性求值无从被注入。
 *
 * 对应 某JSON反序列化库 SupportNonPublicField 修复：关闭非公开字段写入，或显式
 * 字段 allowlist，禁止攻击者篡改内部状态字段。
 *
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM4_PrivateFieldBind_Safe {

    // L2：字段白名单——只允许安全字段
    private static final List<String> ALLOWED_FIELDS = Arrays.asList("label", "timeout");

    public static class CommandTarget {
        @SuppressWarnings("unused")
        private String command; // 危险字段：final/只读，外部不可写
        @SuppressWarnings("unused")
        private String label;

        public void bindField(String name, String value) throws Exception {
            if (!ALLOWED_FIELDS.contains(name)) {
                throw new IllegalArgumentException("field not in allowlist: " + name);
            }
            Field f = CommandTarget.class.getDeclaredField(name);
            f.setAccessible(true);
            f.set(this, value);
        }

        public void execute() throws Exception {
            // 即便执行，也只针对白名单字段，command 不可被外部设置
            System.out.println("execute (safe, no private command bound)");
        }
    }

    public static class EngineTarget {
        // 引擎由服务端固定构造，不暴露可写私有字段
        private final ScriptEngine engine;

        public EngineTarget() {
            this.engine = new ScriptEngineManager().getEngineByName("js");
        }

        public Object evalLazy() throws Exception {
            // 引擎固定，不依赖外部注入
            return engine.eval("localhost-demo"); // 仅占位，不连真实远端
        }
    }

    /**
     * L2 修复：字段绑定走白名单，危险私有字段 command 不可写。
     */
    public void bind(Map<String, String> fields) throws Exception {
        CommandTarget target = new CommandTarget();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            // [SAFE] 字段白名单：危险私有字段 command 被排除
            // [CHECKPOINT id=JSEF-TCM-401S cwe=502 level=L2 source=map field value sink=field allowlist (no private command) expect=SAFE]
            target.bindField(e.getKey(), e.getValue());
        }
        target.execute();
    }

    /**
     * L4 修复：不动态绑定引擎，引擎引用由服务端固定构造。
     */
    public void bindEngine(Map<String, Object> fields) throws Exception {
        EngineTarget target = new EngineTarget();
        for (Map.Entry<String, Object> e : fields.entrySet()) {
            // [SAFE] 无动态引擎绑定：外部 field 不会注入 engine
            // [CHECKPOINT id=JSEF-TCM-402S cwe=502 level=L4 source=map field value sink=no dynamic engine bind expect=SAFE]
            // 服务器固定引擎，忽略外部任何试图写 engine 的字段
            if ("engine".equals(e.getKey())) {
                throw new IllegalArgumentException("dynamic engine bind rejected");
            }
        }
        target.evalLazy();
    }
}
