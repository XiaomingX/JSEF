package com.freedom.securitysamples.api.jndiInjection;

import org.springframework.scripting.ScriptSource;
import org.springframework.scripting.groovy.GroovyScriptEvaluator;
import org.springframework.scripting.support.StaticScriptSource;
import org.springframework.web.bind.annotation.*;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.util.Hashtable;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

@RestController
@RequestMapping("/api")
public class JndiController {

    // 原有的不安全示例
    @GetMapping("/jndi/bad01")
    public String lookupJndiResource(String jndiResourceName) throws NamingException {
        Hashtable<String, String> jndiEnvironment = new Hashtable<>();
        jndiEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        jndiEnvironment.put(Context.PROVIDER_URL, "rmi://trusted-server:1099");
        InitialContext initialContext = new InitialContext(jndiEnvironment);

        // BAD: User input used in lookup
        initialContext.lookup(jndiResourceName);
        return "{'msg':'false'}";
    }

    // 新增: LDAP协议的不安全示例
    @GetMapping("/jndi/bad02")
    public String ldapLookup(String ldapUrl) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        DirContext ctx = new InitialDirContext(env);

        // BAD: 直接使用用户输入进行LDAP查找
        return ctx.lookup(ldapUrl).toString();
    }

    // 新增: 动态构建JNDI URL的不安全示例
    @PostMapping("/jndi/bad03")
    public String dynamicJndiLookup(@RequestBody String userInput) throws NamingException {
        String jndiUrl = "rmi://" + userInput + "/resource";
        Context ctx = new InitialContext();

        // BAD: 动态构建JNDI URL
        return ctx.lookup(jndiUrl).toString();
    }

    // 新增: DNS协议的不安全示例
    @GetMapping("/jndi/bad04")
    public String dnsLookup(String dnsName) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put(Context.PROVIDER_URL, "dns://8.8.8.8");
        Context ctx = new InitialContext(env);

        // BAD: 直接使用用户输入进行DNS查找
        return ctx.lookup(dnsName).toString();
    }

    // 新增: 组合多个协议的不安全示例
    @GetMapping("/jndi/bad05")
    public String multiProtocolLookup(String protocol, String resource) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                protocol.equals("ldap") ? "com.sun.jndi.ldap.LdapCtxFactory" :
                        "com.sun.jndi.rmi.registry.RegistryContextFactory");

        // BAD: 允许用户选择协议和资源
        env.put(Context.PROVIDER_URL, protocol + "://localhost:1099");
        Context ctx = new InitialContext(env);
        return ctx.lookup(resource).toString();
    }

    // 新增: 不安全的JNDI环境变量配置示例
    @GetMapping("/jndi/bad06")
    public String environmentLookup(String factoryUrl, String resourceName) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();

        // BAD: 允许用户控制工厂URL
        env.put(Context.INITIAL_CONTEXT_FACTORY, factoryUrl);
        Context ctx = new InitialContext(env);
        return ctx.lookup(resourceName).toString();
    }
}