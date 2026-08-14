/*
 * JSEF Benchmark 样本 — 弱哈希（D8，CWE-327，L1）
 * 运行态需 JSEF 依赖（Apache Commons Codec 的 DigestUtils 等）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实破解脚本。
 *
 * 知识点（CAP-02/03，L1 单跳）：
 *   用 MD5 哈希密码属弱哈希算法（易碰撞、可查彩虹表），不可用于口令存储。
 *   污点为明文口令，sink 为 MessageDigest.getInstance("MD5") / DigestUtils.md5Hex。
 */
import java.security.MessageDigest;

public class CryptoWeakHash {

    /**
     * 危险入口：MD5 哈希口令。
     */
    static String hashPassword(String plainPassword) throws Exception {
        // source：明文口令（不可信/敏感输入）
        // [CHECKPOINT id=JSEF-CRYPTO-001 cwe=327 level=L1 source=plaintext password sink=MessageDigest.getInstance("MD5") expect=VULN]
        MessageDigest md = MessageDigest.getInstance("MD5");   // 弱哈希
        byte[] d = md.digest(plainPassword.getBytes());
        return bytesToHex(d);
    }

    static String bytesToHex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
}
