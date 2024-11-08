package com.freedom.securitysamples.api.ldapInjection;

import org.springframework.web.bind.annotation.*;
import javax.naming.*;
import javax.naming.directory.*;
import java.util.Hashtable;

@RestController
@RequestMapping("/api")
public class LdapController {

    // 原有的不安全示例
    @GetMapping("/ldap/bad01")
    public String ldapSearch(String userInput) throws NamingException {
        Hashtable<String, String> ldapEnvironment = new Hashtable<>();
        ldapEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        ldapEnvironment.put(Context.PROVIDER_URL, "ldap://localhost:389");

        InitialDirContext ldapContext = new InitialDirContext(ldapEnvironment);

        // 不安全: 未经过滤的用户输入直接用于DN
        String distinguishedName = "OU=People,O=" + userInput;

        // 不安全: 未经过滤的用户输入直接用于搜索过滤器
        String searchFilter = "username=" + userInput;

        ldapContext.search(distinguishedName, searchFilter, new SearchControls());
        return "{'msg':'success'}";
    }

    // 新增不安全示例1: 在LDAP认证中直接使用用户输入
    @PostMapping("/ldap/bad02")
    public String ldapAuth(@RequestParam String username, @RequestParam String password) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");

        // 不安全: 未经过滤的用户输入直接用于绑定DN
        env.put(Context.SECURITY_PRINCIPAL, "cn=" + username + ",dc=example,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, password);

        new InitialDirContext(env);
        return "{'msg':'auth success'}";
    }

    // 新增不安全示例2: 复杂的LDAP查询条件中使用用户输入
    @GetMapping("/ldap/bad03")
    public String complexSearch(@RequestParam String dept, @RequestParam String title) throws NamingException {
        InitialDirContext ctx = getLdapContext();

        // 不安全: 在复杂的过滤条件中直接使用用户输入
        String filter = "(&(department=" + dept + ")(title=" + title + "))";

        ctx.search("dc=example,dc=com", filter, new SearchControls());
        return "{'msg':'search complete'}";
    }

    // 新增不安全示例3: 动态构建搜索基础DN
    @GetMapping("/ldap/bad04")
    public String dynamicBaseDN(@RequestParam String country, @RequestParam String org) throws NamingException {
        InitialDirContext ctx = getLdapContext();

        // 不安全: 动态构建基础DN时直接使用用户输入
        String baseDN = String.format("o=%s,c=%s", org, country);

        ctx.search(baseDN, "(objectClass=person)", new SearchControls());
        return "{'msg':'search complete'}";
    }

    // 新增不安全示例4: 批量操作中使用用户输入
    @PostMapping("/ldap/bad05")
    public String batchOperation(@RequestParam String[] userIds) throws NamingException {
        InitialDirContext ctx = getLdapContext();

        for(String userId : userIds) {
            // 不安全: 批量操作中直接使用用户输入
            String filter = "(uid=" + userId + ")";
            ctx.search("dc=example,dc=com", filter, new SearchControls());
        }
        return "{'msg':'batch operation complete'}";
    }

    // 新增不安全示例5: 动态属性查询
    @GetMapping("/ldap/bad06")
    public String attributeQuery(@RequestParam String attrName, @RequestParam String attrValue) throws NamingException {
        InitialDirContext ctx = getLdapContext();

        // 不安全: 动态构建属性查询时直接使用用户输入
        String filter = "(" + attrName + "=" + attrValue + ")";

        ctx.search("dc=example,dc=com", filter, new SearchControls());
        return "{'msg':'attribute query complete'}";
    }

    private InitialDirContext getLdapContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");
        return new InitialDirContext(env);
    }
}