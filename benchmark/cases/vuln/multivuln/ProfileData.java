package com.jsef.benchmark.vuln.multivuln;

import java.io.Serializable;

/**
 * JSEF-Benchmark 样本族 B — 多漏洞组合链：反序列化载体类（中间层）
 *
 * 角色：ProfileController 未授权反序列化链路的载体 POJO。本文件不设独立
 * checkpoint，仅作为多漏洞组合链第二环（越权读他人数据）的 trace 节点存在。
 *
 * 污点流：ProfileController 收到不可信二进制流后，用 ObjectInputStream
 * 无白名单地反序列化成 ProfileData，再据其中的 userId 读取他人资料。
 *
 * 为什么这里是合理非缺陷：辅助类不单独计 checkpoint，它只是反序列化的
 * 目标类型。被测工具应把本类的反序列化到达（readObject）识别为链路节点。
 *
 * 安全底线：仅 localhost 演示，不写真实攻击载荷。
 */
public class ProfileData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String userId;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
