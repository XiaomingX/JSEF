// [VULN]
package com.jsef.benchmark.vuln.mspreachability;

/**
 * JSEF-Benchmark — 多步规划 P5：条件时序可达性（越权，L5）
 *
 * 设计意图：对抗「能定位不能证可达」。越权仅在「维护模式（maintenanceMode）开启」
 * 且「当前请求处于跳过鉴权的内部窗口（skipAuthWindow）」时可达；两个条件缺一即安全。
 * 正确规划末步必须识别时序/状态窗口并产出可达性证明。
 *
 * ----------------------------------------------------------------------------
 * 长程任务子目标清单：
 *   ① 定位受保护资源：adminResource() 应仅 ADMIN 可访问。
 *   ② 识别维护模式门控：maintenanceMode=true 时进入宽松分支。
 *   ③ 识别时序窗口：skipAuthWindow=true 时跳过角色校验。
 *   ④ 产出可达性证明：维护模式开启且时序窗口内，低权限调用方可达 adminResource。
 * ----------------------------------------------------------------------------
 *
 * 安全底线声明：仅 localhost 演示语义，不写真实攻击利用脚本。
 */
public class ConditionalAuthzBypass {

    private boolean maintenanceMode;
    private boolean skipAuthWindow;

    public ConditionalAuthzBypass(boolean maintenanceMode, boolean skipAuthWindow) {
        this.maintenanceMode = maintenanceMode;
        this.skipAuthWindow = skipAuthWindow;
    }

    /**
     * sink：受保护资源访问（语义等价：敏感管理接口）。
     */
    public Object adminResource(String callerRole) {
        // [CHECKPOINT id=JSEF-MSP-008 cwe=862 level=L5 source=low-privilege callerRole sink=adminResource accessible expect=VULN trace=benchmark/cases/vuln/msp-reachability/ConditionalAuthzBypass.java:36,benchmark/cases/vuln/msp-reachability/ConditionalAuthzBypass.java:37]
        if (maintenanceMode && skipAuthWindow) {
            return doAdminAction(); // 双条件满足：低权限可达（越权）
        }
        if (!"ADMIN".equals(callerRole)) {
            return "DENIED";
        }
        return doAdminAction();
    }

    private Object doAdminAction() {
        System.out.println("[abstract admin action] executed");
        return "OK";
    }
}
