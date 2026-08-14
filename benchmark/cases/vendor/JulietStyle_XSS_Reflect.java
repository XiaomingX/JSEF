package com.jsef.benchmark.vendor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.util.HtmlUtils;

/**
 * JSEF-Benchmark B6 — Juliet 式反射型 XSS 混淆（CWE-79）
 *
 * 抽象自 Juliet (NIST SAMATE) https://samate.nist.gov/SARD/ ，CWE 命名如
 * CWE79_XSS__... 。Juliet 以反射型 XSS 的 good/bad 配对著称。
 *
 * 本文件提供一对紧邻方法：VULN 将 request.getParameter("name") 直接写入响应（未转义），
 * SAFE 用 Spring 的 HtmlUtils.htmlEscape 转义后再输出。难度：L1（混淆类）。
 *
 * 安全底线：Payload 仅 localhost 演示语义，不提供真实利用脚本。
 * 引用框架类说明：演示用 jakarta.servlet + org.springframework.web.util.HtmlUtils，
 * 仅作语义标注，样本用于静态分析/LLM 阅读，不强求编译。
 */
public class JulietStyle_XSS_Reflect {

    /**
     * VULN：反射参数未转义直接回写响应（反射型 XSS）。
     */
    public void reflectVuln(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String name = request.getParameter("name");
        // [CHECKPOINT id=JSEF-VEND-XSS-001 cwe=79 level=L1 source=request.getParameter("name") sink=response.getWriter().print expect=VULN]
        response.getWriter().print(name);
    }

    /**
     * SAFE：输出前用 HtmlUtils.htmlEscape 转义（混淆样本，不应报）。
     */
    public void reflectSafe(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String name = request.getParameter("name");
        // [CHECKPOINT id=JSEF-VEND-XSS-001S cwe=79 level=L1 source=request.getParameter("name") sink=response.getWriter().print expect=SAFE]
        response.getWriter().print(HtmlUtils.htmlEscape(name));
    }
}
