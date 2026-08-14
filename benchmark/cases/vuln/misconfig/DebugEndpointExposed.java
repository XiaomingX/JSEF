/*
 * JSEF Benchmark 样本 — 生产暴露调试/监控端点（A05，CWE-489，L3）
 * 运行态需 JSEF 依赖（Spring Boot Actuator）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实端点探测利用。
 *
 * 知识点（A05 安全配置错误，CWE-489 主动调试代码）：
 *   生产环境未关闭 /actuator 等调试/监控端点，暴露健康检查、env、heapdump 等敏感信息。
 *   属配置/部署错误，非污点流问题，而是"危险终点未禁用"。
 */
import java.util.List;

public class DebugEndpointExposed {

    static final List<String> EXPOSED = List.of("/actuator", "/actuator/env", "/actuator/heapdump", "/debug");

    /**
     * 危险入口：生产环境端点全部暴露且无鉴权。
     */
    static boolean isExposedInProd(String path) {
        // [CHECKPOINT id=JSEF-A05-004 cwe=489 level=L3 source=prod profile sink=/actuator exposed (no auth) expect=VULN]
        return EXPOSED.contains(path);   // 生产中仍可被访问
    }
}
