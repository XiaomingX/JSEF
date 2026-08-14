/*
 * JSEF Benchmark 安全样本 — 生产暴露调试/监控端点（A05，CWE-489，L3）
 * SAFE 版：生产环境禁用 /actuator 调试端点，或加鉴权且仅暴露健康端点。
 * 测试点：强 SAST/LLM 应识别生产已禁用而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import java.util.List;

public class DebugEndpointExposedSafe {

    // 生产仅暴露健康检查（且需鉴权）
    static final List<String> EXPOSED_IN_PROD = List.of("/actuator/health");

    /**
     * 安全入口：生产环境仅暴露必要鉴权端点。
     */
    static boolean isExposedInProd(String path) {
        // [CHECKPOINT id=JSEF-A05-004S cwe=489 level=L3 source=prod profile sink=/actuator restricted (auth required) expect=SAFE]
        return EXPOSED_IN_PROD.contains(path);   // 调试端点已禁用
    }
}
