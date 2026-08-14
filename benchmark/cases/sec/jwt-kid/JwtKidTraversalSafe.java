// [SAFE]
package com.jsef.benchmark.sec;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * JSEF-Benchmark — JWT kid 路径遍历安全对照 (CWE-22，难度 L3)
 *
 * 修复：kid 走白名单 map（id → 安全资源目录内固定文件），拒绝白名单外及
 * 含 ".." 的路径，杜绝任意文件读取。
 */
public class JwtKidTraversalSafe {

    private static final Path KEY_DIR = Paths.get("/etc/app/keys").toAbsolutePath();

    /**
     * 安全：kid 仅允许白名单内的文件名，且必须落在 KEY_DIR 内。
     */
    static java.security.PrivateKey loadKey(DecodedJWT jwt) throws Exception {
        String kid = jwt.getHeaderClaim("kid").asString();
        if (!kid.matches("[a-zA-Z0-9_-]+")) { // 拒绝路径字符
            throw new IllegalArgumentException("invalid kid");
        }
        Path keyPath = KEY_DIR.resolve(kid + ".pem").normalize();
        // [CHECKPOINT id=JSEF-JWTKID-001S cwe=22 level=L3 source=kid header claim sink=whitelist + canonical path check expect=SAFE]
        if (!keyPath.startsWith(KEY_DIR)) {
            throw new IllegalArgumentException("kid escapes key dir");
        }
        byte[] keyBytes = Files.readAllBytes(keyPath);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
}
