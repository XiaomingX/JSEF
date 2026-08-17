package com.jsef.benchmark.sec.gadgetmine;

/*
 * JSEF-Benchmark L5 — Jackson getter 自动调用 gadget 安全对照（CWE-502 / CWE-915）
 *
 * 修复：getter 内无任何危险副作用，仅返回字段值。副作用逻辑不放在 getter 中，
 * 因此 Jackson 自动调用 getter 时不会触发任何危险操作。
 *
 * SAFE 侧按实现判安全：getter 仅返回字段，无 sink 语义。
 */
public class JacksonGetterGadgetSafe {

    /**
     * 教学占位类：getter 安全，无副作用。
     */
    public static class UserStub {
        private String name;
        private String payload;

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
         * 安全 getter：仅返回字段，无危险副作用。
         */
        public String getPayload() {
            // [CHECKPOINT id=JSEF-JGG-001S cwe=502 level=L5 source=untrusted json field sink=getter no side-effect expect=SAFE]
            return payload;
        }
    }

    /**
     * 模拟“框架自动调用 getter”的序列化入口（占位，不依赖真实 Jackson）。
     */
    public static String serialize(UserStub user) {
        return "{\"name\":\"" + user.getName() + "\",\"payload\":\"" + user.getPayload() + "\"}";
    }

    public static void main(String[] args) {
        UserStub user = new UserStub();
        user.setName("victim");
        user.setPayload("touch /tmp/pwned");
        serialize(user);   // 自动调用 getPayload() 无副作用 -> SAFE
    }
}
