package com.jsef.benchmark.vuln;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-522 凭据保护不足：明文存储用户口令，数据库一旦泄露即全部暴露。
 *
 * 修复：使用强哈希算法（如 BCrypt/Argon2/SCrypt）加盐存储，永不存明文。
 */
@RestController
public class PlaintextPasswordStore {

    @PostMapping("/api/v1/cred/unsafe/register")
    public String register(@RequestParam String user, @RequestParam String password) {
        // [CHECKPOINT id=JSEF-COMP-006 cwe=522 level=L1 source=password param sink=db.store(plaintext) expect=VULN]
        storeToDb(user, password); // 明文落库
        return "registered";
    }

    private void storeToDb(String u, String p) { /* 演示：明文写入 */ }
}
