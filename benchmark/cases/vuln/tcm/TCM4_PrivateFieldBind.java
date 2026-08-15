package com.jsef.benchmark.vuln.tcm;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * TCM-4 私有字段可控（Private Field Bind）
 * =========================================
 * 核心范式 P0 的变体：通用「字段绑定器」把攻击者提供的 Map 的 key 当字段名、
 * value 当值，通过 setAccessible(true) 写入对象私有字段，篡改内部状态；
 * 随后对象自身方法（execute / 惰性 getter）读取该私有字段，隐式抵达危险 sink。
 *
 * 对应 某JSON反序列化库 SupportNonPublicField：
 *   开启 SupportNonPublicField 后，反序列化可写私有字段；攻击者可借此篡改
 *   内部本不应被外部设置的字段（如 command / scriptEngine 引用），
 *   从而触发原本无法从外部驱动的危险逻辑。
 *
 * 本样本与任何具体 JSON/序列化库无关，仅用 Java 标准库语义自包含复现。
 * 仅 localhost 演示语义，所有危险调用使用 "localhost-demo" 占位字符串。
 */
public class TCM4_PrivateFieldBind {

    /**
     * L2：私有字段 command 被绑定后，execute() 读该字段 Runtime.exec(command)。
     */
    public static class CommandTarget {
        // 私有字段：本不应被外部直接设置
        @SuppressWarnings("unused")
        private String command;

        public void bindField(String name, String value) throws Exception {
            Field f = CommandTarget.class.getDeclaredField(name);
            f.setAccessible(true); // 写私有字段
            f.set(this, value);
        }

        public void execute() throws Exception {
            // [VULN] 读取被篡改的私有字段，抵达危险 sink
            Runtime.getRuntime().exec(command); // 仅占位，不连真实远端
        }
    }

    /**
     * L4：私有字段为 ScriptEngine 引用，setter 注入引擎后 getter 惰性求值触发 eval。
     */
    public static class EngineTarget {
        // 私有字段：脚本引擎引用（被注入后惰性求值触发 eval）
        @SuppressWarnings("unused")
        private ScriptEngine engine;

        public void bindField(String name, Object value) throws Exception {
            Field f = EngineTarget.class.getDeclaredField(name);
            f.setAccessible(true); // 写入私有字段
            f.set(this, value);
        }

        public Object evalLazy() throws Exception {
            // [VULN] 惰性求值：读取被注入的私有引擎字段，触发 eval
            return engine.eval("localhost-demo"); // 仅占位，不连真实远端
        }
    }

    /**
     * L2：通用字段绑定器——把 map 的 key 当字段名、value 当值，写私有字段。
     */
    public void bind(Map<String, String> fields) throws Exception {
        CommandTarget target = new CommandTarget();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            // [VULN] 字段绑定器写私有字段（含危险字段 command）
            target.bindField(e.getKey(), e.getValue());
        }
        // [CHECKPOINT id=JSEF-TCM-401 cwe=502 level=L2 source=map field value sink=Runtime.exec(privateField) expect=VULN]
        target.execute(); // 读私有字段 command -> Runtime.exec
    }

    /**
     * L4：私有字段绑定引擎，惰性 getter 触发 eval。
     */
    public void bindEngine(Map<String, Object> fields) throws Exception {
        EngineTarget target = new EngineTarget();
        ScriptEngineManager manager = new ScriptEngineManager();
        for (Map.Entry<String, Object> e : fields.entrySet()) {
            Object val = e.getValue();
            if (val == null && "engine".equals(e.getKey())) {
                val = manager.getEngineByName("js"); // 注入脚本引擎
            }
            // [VULN] 私有字段 engine 被外部写入
            target.bindField(e.getKey(), val); // 行：私有字段写入
        }
        // [CHECKPOINT id=JSEF-TCM-402 cwe=502 level=L4 source=map field value sink=ScriptEngine.eval(userScript) expect=VULN trace=benchmark/cases/vuln/tcm/TCM4_PrivateFieldBind.java:90,benchmark/cases/vuln/tcm/TCM4_PrivateFieldBind.java:93]
        target.evalLazy(); // 行：eval 触发（读私有 engine 字段）
    }
}
