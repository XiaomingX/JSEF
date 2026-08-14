/*
 * JSEF Benchmark 安全样本 — 垂直越权/提权（A01，CWE-285，L4）
 * SAFE 版：角色不取自请求体，而是从服务端会话/认证上下文读取并校验，拒绝伪造。
 * 测试点：强 SAST/LLM 应识别角色来自可信会话且已校验而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
public class VerticalPrivEscSafe {

    static final class Account { String username; }
    static final class Session { final String role; Session(String role){ this.role=role; } }   // 角色来自服务端上下文

    /**
     * 安全入口：角色取自可信会话，非请求体绑定。
     */
    static boolean isAdmin(Account account, Session session) {
        // 角色来自服务端会话（不可由客户端伪造），并做显式校验
        // [CHECKPOINT id=JSEF-A01-003S cwe=285 level=L4 source=session role (trusted) sink=authorization decision (role from session) expect=SAFE]
        return "ADMIN".equals(session.role);   // 角色不可由客户端篡改
    }
}
