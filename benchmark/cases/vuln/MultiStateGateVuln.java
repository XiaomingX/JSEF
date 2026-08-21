package com.jsef.benchmark.vuln;

/*
 * 运行态需 JSEF 依赖：本文件引用 SpEL / 配置 / 版本 / 角色语义，用于静态分析 / LLM 阅读，
 * 不强求编译，但语义正确、可读。危险 sink 为语义桩（见 spelParse），不产生真实攻击载荷。
 *
 * JSEF-Benchmark L5 — 多状态联合判定复合门控（SpEL sink，CWE-917）
 *
 * 难度：L5（长程多步可达性证明）。危险 SpEL 求值需要三个**独立状态同时成立**才可达：
 *   ① config.spelEnabled == true   （配置读取节点）
 *   ② version < 2.0                （版本判断节点）
 *   ③ user.role == ADMIN           （角色校验节点）
 * 任一次序的推理都必须跨配置读取 / 版本判断 / 角色校验这 3 个节点，全部满足后才进入 SpEL sink。
 *
 * 难点/区分点（相对现有 config-gated / msp-statemachine 单布尔开关）：
 *   - 现有样本是**单个布尔开关**门控，仅需证明"开关为真"即可达。
 *   - 本样本是**多条件 AND 联合判定**：任一条件缺失则不可达；且三个条件的真值
 *     来自三个独立来源（外部配置、版本号、会话角色），必须跨节点组合才能证明可达。
 *   - 需要证明的不仅是"某开关默认真"，而是"三种不可信状态在此运行环境下同时满足"，
 *     纯语法 SAST 单点命中无法覆盖这种多条件组合门控。
 *
 * CWE-917 (Expression Language Injection / SpEL)。
 * 安全底线：仅展示语义，Payload 仅 localhost 演示，不提供真实利用脚本。
 */
public class MultiStateGateVuln {

    // 语义：三个独立状态的读取器（可被外部配置 / 版本 / 会话注入）
    static class ConfigService {
        // 语义等价：从 PropertySource 读取 feature.spel.enabled，默认 true 且运行态可被覆盖
        boolean spelEnabled() { return true; }
    }

    static class VersionProvider {
        // 语义等价：读取当前运行时版本号（可被 pom/manifest 或运行参数影响）
        double version() { return 1.5; } // < 2.0
    }

    static class RoleResolver {
        // 语义等价：从会话/上下文解析当前用户角色
        String role() { return "ADMIN"; } // 满足 role == ADMIN
    }

    private final ConfigService config;
    private final VersionProvider version;
    private final RoleResolver roles;

    public MultiStateGateVuln(ConfigService config, VersionProvider version, RoleResolver roles) {
        this.config = config;
        this.version = version;
        this.roles = roles;
    }

    /**
     * 危险入口：仅当 (spelEnabled && version<2.0 && role==ADMIN) 同时成立时，
     * 不可信表达式才进入 SpEL 求值（sink）。长程推理需依次通过三个节点。
     *
     * @param userExpression 不可信 SpEL 表达式
     */
    public Object handle(String userExpression) {
        boolean spel = config.spelEnabled(); // 节点① 配置读取
        double ver = version.version();      // 节点② 版本判断
        String role = roles.role();          // 节点③ 角色校验
        // 多状态 AND 联合判定：三条件同时成立才可达
        if (spel && ver < 2.0 && "ADMIN".equals(role)) {
            // [CHECKPOINT id=JSEF-MULTIGATE-001 cwe=917 level=L5 source=userExpression sink=SpelExpressionParser.parseExpression expect=VULN trace=benchmark/cases/vuln/MultiStateGateVuln.java:60,benchmark/cases/vuln/MultiStateGateVuln.java:61,benchmark/cases/vuln/MultiStateGateVuln.java:62]
            return spelParse(userExpression); // 语义等价: SpelExpressionParser.parseExpression(userExpression).getValue()
        }
        return "gate-closed";
    }

    // 语义桩：VULN 侧信方法名/注释声明（AGENTS.md 抽象桩约定）
    private Object spelParse(String expr) {
        System.out.println("[spel-eval] " + expr); // 语义等价: SpelExpressionParser.parseExpression(expr).getValue()
        return expr;
    }

    public static void main(String[] args) {
        // 组合：三状态同时满足（演示可达），仅 localhost
        new MultiStateGateVuln(new ConfigService(), new VersionProvider(), new RoleResolver())
                .handle("T(java.lang.Runtime)");
    }
}
