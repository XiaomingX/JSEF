package com.freedom.securitysamples.api.thirdParty;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

@RestController
@RequestMapping("/api/xstream")
public class XstreamController {

    // 不安全的XStream配置示例1：直接使用默认配置
    @PostMapping("/unsafe1")
    public String unsafeDeserialization1(@RequestBody String xmlData) {
        XStream xstream = new XStream();
        // 危险：未进行任何安全配置
        Object obj = xstream.fromXML(xmlData);
        return "处理完成：" + obj.toString();
    }

    // 不安全的XStream配置示例2：允许所有类型
    @PostMapping("/unsafe2")
    public String unsafeDeserialization2(@RequestBody String xmlData) {
        XStream xstream = new XStream(new DomDriver());
        xstream.allowTypes(new Class[]{Object.class});  // 危险：允许所有类型
        return "结果：" + xstream.fromXML(xmlData);
    }

    // 不安全的XStream配置示例3：动态类加载
    @PostMapping("/unsafe3")
    public String unsafeDeserialization3(@RequestBody String xmlData) {
        XStream xstream = new XStream();
        xstream.allowTypesByWildcard(new String[]{"com.freedom.**"});  // 危险：过于宽松的通配符
        return "处理结果：" + xstream.fromXML(xmlData);
    }

    // 不安全的XStream配置示例4：文件操作结合
    @PostMapping("/unsafe4")
    public String unsafeDeserialization4(@RequestBody String xmlData) {
        try {
            XStream xstream = new XStream();
            // 危险：将不受信任的数据序列化到文件
            File tempFile = new File("temp.xml");
            FileOutputStream fos = new FileOutputStream(tempFile);
            fos.write(xmlData.getBytes());
            fos.close();

            // 危险：从文件读取并反序列化
            FileInputStream fis = new FileInputStream(tempFile);
            Object obj = xstream.fromXML(fis);
            fis.close();
            return "文件处理完成：" + obj.toString();
        } catch (IOException e) {
            return "错误：" + e.getMessage();
        }
    }

    // 不安全的XStream配置示例5：自定义转换器
    @PostMapping("/unsafe5")
    public String unsafeDeserialization5(@RequestBody String xmlData) {
        XStream xstream = new XStream();
        // 危险：注册自定义转换器但未进行安全检查
        xstream.registerConverter(new CustomConverter());
        return "转换结果：" + xstream.fromXML(xmlData);
    }

    // 不安全的XStream配置示例6：远程加载
    @PostMapping("/unsafe6")
    public String unsafeDeserialization6(@RequestBody String xmlData) {
        XStream xstream = new XStream();
        // 危险：启用外部实体解析
        xstream.allowTypes(new Class[]{java.net.URL.class});
        return "远程加载结果：" + xstream.fromXML(xmlData);
    }
}

// 自定义转换器示例（不安全）
class CustomConverter implements com.thoughtworks.xstream.converters.Converter {
    @Override
    public boolean canConvert(Class type) {
        return true; // 危险：接受所有类型
    }

    @Override
    public void marshal(Object source, com.thoughtworks.xstream.io.HierarchicalStreamWriter writer,
                        com.thoughtworks.xstream.converters.MarshallingContext context) {
        // 实现序列化逻辑
    }

    @Override
    public Object unmarshal(com.thoughtworks.xstream.io.HierarchicalStreamReader reader,
                            com.thoughtworks.xstream.converters.UnmarshallingContext context) {
        // 危险：未进行任何安全检查的反序列化
        return context.convertAnother(reader, Object.class);
    }
}