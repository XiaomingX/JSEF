package com.jsef.benchmark.vuln.multivuln;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayOutputStream;

/**
 * JSEF-Benchmark 样本族 B — 多漏洞组合链：第二环 · 越权读他人数据（CWE-502 + 639，L5）
 *
 * 难度：L5（多漏洞类型串成完整链的终点）
 *
 * 整条链（两种不同漏洞先后利用才达成目标）：
 *   环1 信息泄露（AuditLogVault，CWE-532，子 checkpoint JSEF-OS-004A）：
 *     不可信请求中的 userId 被原样写日志（AuditLogVault.java:29）——攻击者
 *     借此拿到他人 userId。
 *   环2 未授权反序列化 + 越权（本文件，主 checkpoint JSEF-OS-004）：
 *     攻击者把泄露出的 userId 塞进不可信二进制流，经无白名单的
 *     ObjectInputStream 反序列化成 ProfileData（本文件反序列化行），
 *     再据其中的 userId 直接读取他人资料——未做归属校验的越权。
 *
 * 为什么是"多漏洞组合链"：现有 gadget chain 是单漏洞类型内多类组合；
 * 本链把"信息泄露（CWE-532）"与"越权/反序列化（CWE-639+502）"两种不同
 * 漏洞串成必须先后利用的完整攻击路径。单漏洞检测只能各自报一条独立
 * 漏洞；只有沿"日志泄露 → 凭据获取 → 越权数据访问"的编排推理，才能
 * 还原这是同一目标上的一次完整多步利用。
 *
 * 主 checkpoint（JSEF-OS-004）落在第二环越权数据访问 sink 行；第一环
 * 信息泄露用子 id（JSEF-OS-004A），两个 checkpoint 归属同一目标但不同行。
 *
 * 修复要点：环1 日志脱敏；环2 反序列化加类型白名单并做归属校验。对照
 * ProfileControllerSafe。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
@RestController
public class ProfileController {

    private final AuditLogVault vault = new AuditLogVault();

    /**
     * 危险入口：接收不可信二进制流，反序列化后直接读他人资料。
     */
    @PostMapping("/benchmark/multivuln/profile")
    public String fetchProfile(@RequestBody byte[] payload) throws Exception {
        // 中间节点：不可信流经无白名单反序列化成 ProfileData
        ProfileData data = deserialize(payload); // 反序列化行（中间节点，见本文件下方方法）

        // 第一环交互：把反序列化出的 userId 交给审计日志（信息泄露联动）
        String leakedUserId = data.getUserId();
        vault.logAccess(leakedUserId);

        // [CHECKPOINT id=JSEF-OS-004 cwe=639+502 level=L5 source=leaked userId via untrusted deserialization sink=read other user profile without ownership check expect=VULN trace=benchmark/cases/vuln/multivuln/AuditLogVault.java:29,benchmark/cases/vuln/multivuln/ProfileController.java:51]
        return readProfile(leakedUserId); // 越权读他人数据：无归属校验的敏感读
    }

    /**
     * 语义等价：ObjectInputStream.readObject() —— 无类型白名单（危险反序列化）。
     */
    static ProfileData deserialize(byte[] payload) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        Object obj = ois.readObject(); // 中间节点：反序列化到达（无白名单）
        ois.close();
        return (ProfileData) obj;
    }

    /**
     * 语义等价：根据 userId 读取用户资料（危险 sink，未做归属校验）。
     */
    static String readProfile(String userId) {
        // 语义等价：profileRepository.findByUserId(userId) —— 越权读取他人数据
        System.out.println("[profile-read] userId=" + userId);
        return "profile-data:" + userId;
    }

    /** 序列化辅助（演示用，localhost only）。 */
    static byte[] serialize(ProfileData p) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(p);
        oos.close();
        return bos.toByteArray();
    }
}
