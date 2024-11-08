package com.freedom.securitysamples.cve;


//https://forum.butian.net/share/2373
//CVE-2023-34034 是 Spring WebFlux 框架中的一个严重漏洞，具体涉及 Spring Security。此漏洞是由于在 Spring Security 的 WebFlux 配置中使用双通配符“**”时出现的模式匹配问题。从本质上讲，这会导致 Spring Security 和 Spring WebFlux 之间的模式匹配不匹配，从而为安全绕过创造了可能性。
public class CVE202334034 {
    public static void main(String[] argv){

    }
}
