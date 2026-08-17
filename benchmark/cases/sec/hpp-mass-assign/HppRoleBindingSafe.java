package com.jsef.benchmark.sec;

import java.util.Arrays;

/*
 * JSEF-Benchmark L4 — HPP 角色绑定修复 (CWE-915) expect=SAFE
 *
 * sec 侧：单一取值 req.getParam("roles")（仅首个），忽略重复参数，
 * 或固定为 USER，避免攻击者借重复参数注入 ADMIN。
 *
 * 安全底线：按实现判定为安全。
 */
public class HppRoleBindingSafe {

    static class Req {
        String getParam(String name) {
            return "USER"; // 仅取首个 / 忽略重复参数
        }
    }

    static class Account {
        void setRoles(java.util.List<String> roles) {
            System.out.println("[bind-roles] " + roles);
        }
    }

    // [CHECKPOINT id=JSEF-NV401S cwe=915 level=L4 source=roles (single-value) sink=setRoles(bound list) expect=SAFE trace=benchmark/cases/sec/hpp-mass-assign/HppRoleBindingSafe.java:30,benchmark/cases/sec/hpp-mass-assign/HppRoleBindingSafe.java:31]
    public void bind(Req req, Account acc) {
        // 单一取值，重复参数被忽略
        String role = req.getParam("roles");
        acc.setRoles(Arrays.asList(role));
    }
}
