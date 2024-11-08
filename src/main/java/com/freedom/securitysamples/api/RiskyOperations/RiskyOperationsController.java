package com.freedom.securitysamples.api.RiskyOperations;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import sun.misc.Unsafe;
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;

import java.lang.reflect.Field;

@RestController
@RequestMapping("/api")
public class RiskyOperationsController {

    private static final Unsafe unsafe;

    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafe = (Unsafe) f.get(null);
        } catch (Exception e) {
            throw new RuntimeException("Unable to obtain Unsafe instance", e);
        }
    }

    @GetMapping("/unsafe/mapping")
    public String unsafeMapping(@RequestParam(required = false) String input) {
        // 直接将用户输入传递给 Unsafe 实例（危险操作，切勿在生产环境中使用）
        if (input != null) {
            try {
                long address = Long.parseLong(input);
                // 读取指定内存地址的值（仅作演示，极其危险）
                int value = unsafe.getInt(address);
                return "{'status':'success','data':'从内存地址读取的值: " + value + "'}";
            } catch (NumberFormatException e) {
                return "{'status':'error','msg':'输入的地址格式无效'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'无法读取指定内存地址'}";
            }
        }
        return "{'status':'error','msg':'输入为空'}";
    }

    // 更多常见的 sun.misc.Unsafe 错误写法示例

    @GetMapping("/unsafe/allocate")
    public String unsafeAllocate(@RequestParam(required = false) Long size) {
        // 使用 Unsafe 直接分配内存，不受 JVM 管控，容易导致内存泄漏
        if (size != null && size > 0) {
            try {
                long address = unsafe.allocateMemory(size);
                return "{'status':'success','data':'已分配内存地址: " + address + "'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'内存分配失败'}";
            }
        }
        return "{'status':'error','msg':'无效的内存大小'}";
    }

    @GetMapping("/unsafe/free")
    public String unsafeFree(@RequestParam(required = false) Long address) {
        // 使用 Unsafe 释放内存，释放错误地址可能导致 JVM 崩溃
        if (address != null) {
            try {
                unsafe.freeMemory(address);
                return "{'status':'success','msg':'内存已释放'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'内存释放失败'}";
            }
        }
        return "{'status':'error','msg':'无效的内存地址'}";
    }

    @GetMapping("/unsafe/object")
    public String unsafeObjectManipulation(@RequestParam(required = false) String input) {
        // 使用 Unsafe 操作对象字段，跳过构造函数，可能导致对象处于不一致状态
        if (input != null) {
            try {
                DummyObject obj = (DummyObject) unsafe.allocateInstance(DummyObject.class);
                obj.setData(input);  // 可能导致对象不一致或未正确初始化
                return "{'status':'success','data':'对象已创建: " + obj + "'}";
            } catch (InstantiationException e) {
                return "{'status':'error','msg':'对象创建失败'}";
            }
        }
        return "{'status':'error','msg':'输入为空'}";
    }

    @GetMapping("/rmi")
    public String rmiInput(@RequestParam String input) {
        try {
            // 假设RMI服务已经在远程主机上注册，绑定名为"RemoteService"
            RemoteService remoteService = (RemoteService) Naming.lookup("rmi://localhost:1099/RemoteService");
            // 使用RMI远程调用服务
            String response = remoteService.processInput(input);
            return "RMI Response: " + response;
        } catch (Exception e) {
            e.printStackTrace();
            return "Error during RMI call: " + e.getMessage();
        }
    }

    // 定义一个RMI服务的接口
    public interface RemoteService extends Remote {
        String processInput(String input) throws RemoteException;
    }
    @GetMapping("/unsafe/cas")
    public String unsafeCompareAndSwap(@RequestParam(required = false) Long address, @RequestParam(required = false) Integer expected, @RequestParam(required = false) Integer newValue) {
        // 使用 Unsafe 进行不正确的 Compare-And-Swap 操作，可能导致数据不一致
        if (address != null && expected != null && newValue != null) {
            try {
                boolean success = unsafe.compareAndSwapInt(null, address, expected, newValue);
                return "{'status':'success','msg':'CAS 操作: " + (success ? "成功" : "失败") + "'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'CAS 操作失败'}";
            }
        }
        return "{'status':'error','msg':'无效的输入参数'}";
    }

    @GetMapping("/unsafe/put")
    public String unsafePutValue(@RequestParam(required = false) Long address, @RequestParam(required = false) Integer value) {
        // 使用 Unsafe 直接向内存地址写入数据，容易导致程序崩溃或内存损坏
        if (address != null && value != null) {
            try {
                unsafe.putInt(address, value);
                return "{'status':'success','msg':'值已写入内存地址'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'写入内存地址失败'}";
            }
        }
        return "{'status':'error','msg':'无效的输入参数'}";
    }

    @GetMapping("/unsafe/get")
    public String unsafeGetValue(@RequestParam(required = false) Long address) {
        // 使用 Unsafe 从任意内存地址读取数据，可能导致安全隐患和崩溃
        if (address != null) {
            try {
                int value = unsafe.getInt(address);
                return "{'status':'success','data':'读取的内存值: " + value + "'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'读取内存值失败'}";
            }
        }
        return "{'status':'error','msg':'无效的内存地址'}";
    }

    @GetMapping("/unsafe/park")
    public String unsafeParkThread(@RequestParam(required = false) Long delay) {
        // 使用 Unsafe 强制挂起线程，可能导致程序无法正常响应
        if (delay != null && delay > 0) {
            try {
                unsafe.park(false, delay);
                return "{'status':'success','msg':'线程已挂起'}";
            } catch (Exception e) {
                return "{'status':'error','msg':'线程挂起失败'}";
            }
        }
        return "{'status':'error','msg':'无效的延迟时间'}";
    }

    @GetMapping("/unsafe/unpark")
    public String unsafeUnparkThread() {
        // 使用 Unsafe 强制恢复线程，容易引起线程管理问题
        try {
            Thread currentThread = Thread.currentThread();
            unsafe.unpark(currentThread);
            return "{'status':'success','msg':'线程已恢复'}";
        } catch (Exception e) {
            return "{'status':'error','msg':'线程恢复失败'}";
        }
    }

    static class DummyObject {
        private String data;

        public void setData(String data) {
            this.data = data;
        }

        @Override
        public String toString() {
            return "DummyObject{data='" + data + "'}";
        }
    }
}
