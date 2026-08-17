package com.jsef.benchmark.vuln.gadgetmine;

/*
 * JSEF-Benchmark L5 — Jackson getter 自动调用 gadget（CWE-502 / CWE-915）
 *
 * 验收点：Jackson 在反序列化/序列化（readValue / writeValue）期间会**自动调用**
 * 所有 public getter（getX()）来构造或输出字段。攻击者若能在被反序列化类里
 * 控制一个 getter 的方法体，就可在“框架自动调用路径”上触发危险副作用——
 * 触发点并非调用方显式写出 sink，而是 Jackson 内部反射 invoke。
 *
 * 本样本不 import 任何真实 Jackson 类，仅用教学占位类 UserStub 模拟该语义：
 *   - setXxx() 设置字段；
 *   - getXxx() 被“框架自动调用”，其方法体内嵌模拟危险 sink（语义等价
 *     Runtime.exec，仅 localhost 演示：打印命令并写本地 marker，不真正执行）。
 *
 * 被测工具需识别：“getter 自动调用”即可达危险副作用，而非依赖显式 sink 调用点。
 *
 * 安全底线：仅 localhost 演示语义，不写真实攻击利用脚本，不真正执行命令。
 *
 * 修复要点（对照 JacksonGetterGadgetSafe.java）：getter 内不得有任何危险副作用，
 * 仅返回字段；或将副作用逻辑移出 getter 由显式业务方法调用。
 */
public class JacksonGetterGadget {

    /**
     * 教学占位类：模拟被 Jackson 反序列化的 POJO。
     * 真实场景中由 ObjectMapper 反射调用其 getter/setter。
     */
    public static class UserStub {
        private String name;
        private String payload;   // 攻击者可控字段

        public void setName(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        public void setPayload(String payload) {
            this.payload = payload;
        }

        /**
         * 危险 getter：Jackson 序列化/反序列化时自动调用。
         * 语义等价 Runtime.exec(payload) —— 仅 localhost 演示。
         */
        public String getPayload() {
            // [CHECKPOINT id=JSEF-JGG-001 cwe=502 level=L5 source=untrusted json field sink=getter auto-invocation -> Runtime.exec (Jackson gadget) expect=VULN trace=benchmark/cases/vuln/gadgetmine/JacksonGetterGadget.java:36,benchmark/cases/vuln/gadgetmine/JacksonGetterGadget.java:48,benchmark/cases/vuln/gadgetmine/JacksonGetterGadget.java:53]
            return invokeDangerousSideEffect(payload);   // 框架自动调用此 getter -> 触发副作用
        }

        // 抽象 sink：语义等价 Runtime.getRuntime().exec(cmd)。仅 localhost 演示。
        // 不真正执行命令；打印命令并写本地 marker 表示“已触发”。
        static String invokeDangerousSideEffect(String cmd) {
            System.out.println("[cmd-exec] (localhost demo only) " + cmd);
            System.out.println("[marker] gadget side-effect triggered");
            return cmd;
        }
    }

    /**
     * 模拟“框架自动调用 getter”的序列化入口（占位，不依赖真实 Jackson）。
     * 真实场景由 ObjectMapper.writeValueAsString(user) 自动触发 getPayload()。
     */
    public static String serialize(UserStub user) {
        // Jackson 自动调用所有 getter；此处模拟该反射调用语义
        return "{\"name\":\"" + user.getName() + "\",\"payload\":\"" + user.getPayload() + "\"}";
    }

    public static void main(String[] args) {
        UserStub user = new UserStub();
        user.setName("victim");
        user.setPayload("touch /tmp/pwned");   // 攻击者通过 JSON 字段注入
        serialize(user);                          // Jackson 自动调用 getPayload() -> 触发副作用
    }
}
