/*
 * JSEF Benchmark 样本 — AES-GCM 重用 IV（A02，CWE-329，L3）
 * 运行态需 JSEF 依赖（javax.crypto）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实密钥恢复利用。
 *
 * 知识点（A02 加密缺陷，CWE-329 生成的随机数可被预测）：
 *   AES-GCM 要求每次加密使用唯一 IV，本例复用固定 IV 加密多条消息，
 *   攻击者可由重用的密文对恢复明文/伪造 tag。数据流：固定 IV → Cipher.init(GCM) → doFinal。
 */
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ReusedIv {

    private static final byte[] KEY = "mysecretkey1234".getBytes();
    private static final byte[] FIXED_IV = new byte[12];   // 危险：固定 IV 复用

    /**
     * 危险入口：每次加密复用同一 IV。
     */
    static String encrypt(String plainText) throws Exception {
        SecretKeySpec key = new SecretKeySpec(KEY, "AES");
        // [CHECKPOINT id=JSEF-A02-002 cwe=329 level=L3 source=fixed IV (reused) sink=Cipher(AES/GCM, reused IV) expect=VULN]
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, FIXED_IV));   // IV 复用
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }
}
