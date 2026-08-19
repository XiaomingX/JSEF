package com.jsef.benchmark.sec.multivuln;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Set;

/**
 * JSEF-Benchmark 样本族 B — 多漏洞组合链安全对照（CWE-639+502，L5）
 *
 * 难度：L5（链条被两处打断，终点不可达）
 *
 * 与 vuln/multivuln/ProfileController 同构的多漏洞组合链，但链条被两处修复
 * 打断，因此 expect=SAFE：
 *   环1（信息泄露）：日志不再记录原始 userId，只记录脱敏掩码 —— 攻击者
 *       无法从日志拿到他人 id。
 *   环2（反序列化+越权）：反序列化加类型白名单，非 ProfileData 白名单
 *       类型直接 throw；且读资料前做归属校验 —— 无法用篡改数据越权。
 *
 * 测试点：强 SAST/LLM 应识别链条在环1、环2 均被打断而不报（TN）；弱工具
 * 易因"看到 ObjectInputStream / 读到 userId"误报（测 FP）。
 *
 * 修复要点：日志脱敏 + 反序列化白名单 + 归属校验。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
@RestController
public class ProfileControllerSafe {

    /** 反序列化类型白名单：仅允许本样本的载体类型。 */
    private static final Set<Class<?>> ALLOWED_TYPES = Set.of(ProfileRecord.class);

    private final MaskedAuditLog auditLog = new MaskedAuditLog();

    /**
     * 安全入口：白名单反序列化 + 日志脱敏 + 归属校验。
     */
    @PostMapping("/benchmark/multivuln/profile/safe")
    public String fetchProfile(@RequestBody byte[] payload, @RequestBody CallerPrincipal caller) throws Exception {
        // 白名单反序列化：非白名单类型抛异常（链条在环2 起点被打断）
        ProfileRecord data = deserialize(payload);
        if (data == null) {
            return "REJECTED";
        }
        // 归属校验：仅允许读取当前调用者自己的资料
        // [CHECKPOINT id=JSEF-OS-004S cwe=639+502 level=L5 source=caller principal sink=profile read guarded by ownership check expect=SAFE]
        if (!caller.owns(data)) {
            return "DENIED";
        }
        // 日志脱敏：仅记录掩码后的 id，不泄漏原始 userId
        auditLog.logAccessMasked(data.getUserId());
        return readProfile(data.getUserId());
    }

    /**
     * 语义等价：ObjectInputStream.readObject() + 白名单校验。
     */
    static ProfileRecord deserialize(byte[] payload) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        Object obj = ois.readObject();
        ois.close();
        if (!ALLOWED_TYPES.contains(obj.getClass())) {
            throw new SecurityException("forbidden type: " + obj.getClass());
        }
        return (ProfileRecord) obj;
    }

    /** 语义等价：读取用户资料（经归属校验后，仅本人才可）。 */
    static String readProfile(String userId) {
        System.out.println("[profile-read-safe] userId=" + userId);
        return "profile-data:" + userId;
    }

    /** 安全审计日志桩：日志脱敏，不写原始 userId。 */
    static class MaskedAuditLog {
        /** 语义等价：logger.info("access by user={}", mask(userId)) —— 脱敏。 */
        void logAccessMasked(String userId) {
            String masked = userId == null || userId.length() < 2 ? "****"
                    : userId.substring(0, 1) + "***";
            System.out.println("[audit-safe] access by user=" + masked);
        }
    }

    /** 反序列化载体（白名单内类型）。 */
    static class ProfileRecord {
        private String userId;
        String getUserId() { return userId; }
        void setUserId(String userId) { this.userId = userId; }
    }

    /** 调用者主体：用于归属校验。 */
    static class CallerPrincipal {
        private final String currentUserId;
        CallerPrincipal(String currentUserId) { this.currentUserId = currentUserId; }
        boolean owns(ProfileRecord data) {
            return currentUserId.equals(data.getUserId());
        }
    }
}
