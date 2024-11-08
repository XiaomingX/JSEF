package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

@RestController
@RequestMapping("/proxy")

//### JDK 动态代理概述
//**JDK 动态代理**是一种 Java 机制，用于在运行时创建代理对象，代理指定接口的方法来控制目标对象的行为。
//        #### 核心组件
//1. **InvocationHandler 接口**
//        - 编写代理逻辑的接口。
//        - 包含一个 `invoke` 方法，用于拦截和处理对目标方法的调用。
//        2. **Proxy 类**
//        - 用于生成代理对象。
//        - 提供 `newProxyInstance` 方法来创建代理实例。

public class ProxyController {
    
    // 定义接口
    interface UserService {
        String getUser(String userId);
    }
    
    // 实现类
    static class UserServiceImpl implements UserService {
        @Override
        public String getUser(String userId) {
            return "用户ID: " + userId;
        }
    }
    
    // 自定义InvocationHandler
    static class LogHandler implements InvocationHandler {
        private final Object target;
        
        public LogHandler(Object target) {
            this.target = target;
        }
        
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            System.out.println("开始调用方法: " + method.getName());
            long startTime = System.currentTimeMillis();
            
            Object result = method.invoke(target, args);
            
            long endTime = System.currentTimeMillis();
            System.out.println("方法执行时间: " + (endTime - startTime) + "ms");
            
            return result;
        }
    }
    
    private UserService createProxy() {
        UserService target = new UserServiceImpl();
        return (UserService) Proxy.newProxyInstance(
            target.getClass().getClassLoader(),
            target.getClass().getInterfaces(),
            new LogHandler(target)
        );
    }
    
    @GetMapping("/demo")
    public String proxyDemo() {
        UserService userService = createProxy();
        return userService.getUser("12345");
    }

    
}