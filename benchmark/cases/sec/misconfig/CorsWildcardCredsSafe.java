/*
 * JSEF Benchmark 安全样本 — CORS 通配符带凭证（A05，CWE-942，L3）
 * SAFE 版：Access-Control-Allow-Origin 设为固定白名单源，且按需允许凭证（不配合 *）。
 * 测试点：强 SAST/LLM 应识别来源受限而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
import java.util.Map;

public class CorsWildcardCredsSafe {

    static final String ALLOWED = "https://app.example.com";

    /**
     * 安全入口：固定白名单源。
     */
    static Map<String, String> buildCorsHeaders() {
        // [CHECKPOINT id=JSEF-A05-001S cwe=942 level=L3 source=cors config sink=Access-Control-Allow-Origin: whitelist (no *) expect=SAFE]
        return Map.of(
            "Access-Control-Allow-Origin", ALLOWED,        // 固定白名单
            "Access-Control-Allow-Credentials", "true");
    }
}
