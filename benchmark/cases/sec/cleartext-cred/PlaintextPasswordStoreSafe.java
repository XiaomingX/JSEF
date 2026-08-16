package com.jsef.benchmark.sec;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * CWE-522 修复：使用 BCrypt 加盐哈希存储口令。
 */
@RestController
public class PlaintextPasswordStoreSafe {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    @PostMapping("/api/v1/cred/safe/register")
    public String register(@RequestParam String user, @RequestParam String password) {
        // [CHECKPOINT id=JSEF-COMP-006S cwe=522 level=L1 source=password param sink=encoder.encode (bcrypt hash) expect=SAFE]
        String hash = encoder.encode(password); // 仅存哈希
        storeToDb(user, hash);
        return "registered";
    }

    private void storeToDb(String u, String h) { /* 存哈希值 */ }
}
