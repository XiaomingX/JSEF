// [VULN]
package com.jsef.benchmark.vuln.bizlogic5;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * JSEF-Benchmark L5 — 业务逻辑漏洞：Incorrect Permission Assignment (CWE-732)
 *
 * 危险权限赋权：用户上传文件时自带的权限模式（mode）被原样用于落盘，
 * 系统未做降权/白名单，导致攻击者可将敏感文件设为全局可写/可执行。
 *
 * 区分度来源（L5 跨文件）：
 *   权限值来自用户请求（source），跨 3 个编译单元一路到达文件系统 sink：
 *     FileUploadController (source: @RequestParam mode)
 *       -> StorageService.store(file, mode)        [原样透传权限模式]
 *       -> FilePermissionGateway.apply(file, mode) [sink: 设置文件权限]
 *
 * VulnGym 范式对齐：BL-PRIV-ESC（权限提升）—— 非授权获得对文件的写/执行权。
 * 纯语法 SAST 若只看 StorageService 看不到"mode 来自用户输入"。
 */
@RestController
public class FileUploadController {

    private final StorageService storageService;

    public FileUploadController(StorageService storageService) {
        this.storageService = storageService;
    }

    @PostMapping("/api/v1/files/upload")
    public String upload(@RequestParam("name") String name,
                         @RequestParam("content") String content,
                         @RequestParam("mode") String mode) {
        // 入口：mode（权限八进制串）来自外部请求参数（source）
        // 缺陷：未校验 mode 是否在安全白名单（如仅 0644），直接下发
        // [CHECKPOINT id=JSEF-BIZ5-732-001 cwe=732 level=L5 source=@RequestParam mode (attacker-controlled permission) sink=StorageService.store expect=VULN trace=benchmark/cases/vuln/bizlogic5/StorageService.java:21,benchmark/cases/vuln/bizlogic5/FilePermissionGateway.java:16]
        return storageService.store(name, content, mode);
    }
}
