package com.freedom.securitysamples.api.pathTraversal;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

// 路径遍历漏洞示例集合
@RestController
@RequestMapping("/api/path")
public class PathTraversalController {

    private static final String BASE_PATH = "/tmp/uploads/";

    // 1. 原始的不安全读取文件示例
    @RequestMapping("/bad01")
    public String readFileContent(String filePath) throws IOException {
        File file = new File(filePath);
        if (file.exists()) {
            byte[] fileData = Files.readAllBytes(Paths.get(filePath));
            return new String(fileData);
        }
        return filePath;
    }

    // 2. 不安全的文件下载
    @GetMapping("/bad02/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam String fileName) throws IOException {
        Path path = Paths.get(BASE_PATH + fileName);
        Resource resource = new UrlResource(path.toUri());
        return ResponseEntity.ok().body(resource);
    }

    // 3. 不安全的文件上传路径处理
    @PostMapping("/bad03/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file, @RequestParam("directory") String directory) throws IOException {
        String uploadPath = BASE_PATH + directory + "/" + file.getOriginalFilename();
        File dest = new File(uploadPath);
        file.transferTo(dest);
        return "File uploaded to: " + uploadPath;
    }

    // 4. 不安全的ZIP文件解压
    @PostMapping("/bad04/unzip")
    public String unzipFile(@RequestParam("zipFile") MultipartFile zipFile, @RequestParam("extractPath") String extractPath) throws IOException {
        File destDir = new File(extractPath);
        byte[] buffer = new byte[1024];
        ZipInputStream zis = new ZipInputStream(zipFile.getInputStream());
        ZipEntry zipEntry = zis.getNextEntry();
        while (zipEntry != null) {
            File newFile = new File(destDir, zipEntry.getName());
            FileOutputStream fos = new FileOutputStream(newFile);
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
            zipEntry = zis.getNextEntry();
        }
        zis.closeEntry();
        zis.close();
        return "Unzipped to: " + extractPath;
    }

    // 5. 不安全的文件删除
    @DeleteMapping("/bad05/delete")
    public String deleteFile(@RequestParam String filePath) {
        File file = new File(BASE_PATH + filePath);
        if (file.delete()) {
            return "File deleted successfully";
        }
        return "Failed to delete file";
    }

    // 6. 不安全的文件读取流
    @GetMapping("/bad06/stream")
    public void streamFile(@RequestParam String filePath, OutputStream outputStream) throws IOException {
        FileInputStream inputStream = new FileInputStream(BASE_PATH + filePath);
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        inputStream.close();
    }

    // 7. 不安全的文件写入
    @PostMapping("/bad07/write")
    public String writeFile(@RequestParam String content, @RequestParam String filePath) throws IOException {
        FileWriter writer = new FileWriter(BASE_PATH + filePath);
        writer.write(content);
        writer.close();
        return "Content written to file";
    }

    // 8. 不安全的文件重命名
    @PutMapping("/bad08/rename")
    public String renameFile(@RequestParam String oldPath, @RequestParam String newPath) {
        File oldFile = new File(BASE_PATH + oldPath);
        File newFile = new File(BASE_PATH + newPath);
        if (oldFile.renameTo(newFile)) {
            return "File renamed successfully";
        }
        return "Failed to rename file";
    }
}