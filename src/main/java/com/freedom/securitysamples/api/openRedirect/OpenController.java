package com.freedom.securitysamples.api.openRedirect;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;

@Controller
@RequestMapping("/api")
public class OpenController {

    // 案例1: 直接拼接URL
    @GetMapping("/Open/bad01")
    public String UnvalidatedRedirect(String url){
        return "redirect:" + url;
    }

    // 案例2: 使用ModelAndView但未验证
    @GetMapping("/Open/bad02")
    public ModelAndView redirectWithModelAndView(@RequestParam String url) {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("redirect:" + url);
        return mav;
    }

    // 案例3: 使用RedirectView但未验证
    @GetMapping("/Open/bad03")
    public RedirectView redirectWithRedirectView(@RequestParam String url) {
        return new RedirectView(url);
    }

    // 案例4: 使用forward但未验证
    @GetMapping("/Open/bad04")
    public String forwardRequest(@RequestParam String url) {
        return "forward:" + url;
    }

    // 案例5: 使用response.sendRedirect但未验证
    @GetMapping("/Open/bad05")
    public void redirectWithResponse(HttpServletResponse response, @RequestParam String url)
            throws IOException {
        response.sendRedirect(url);
    }

    // 案例6: 简单的URL校验但仍可被绕过
    @GetMapping("/Open/bad06")
    public String redirectWithSimpleValidation(@RequestParam String url) {
        if(url.startsWith("http://") || url.startsWith("https://")) {
            return "redirect:" + url;
        }
        return "redirect:/home";
    }

    // 案例7: 使用URL拼接但未转义
    @GetMapping("/Open/bad07")
    public String redirectWithUrlJoin(@RequestParam String path) {
        return "redirect:https://example.com/" + path;
    }

    // 案例8: 接收多个参数拼接但未验证
    @GetMapping("/Open/bad08")
    public String redirectWithParams(@RequestParam String domain,
                                     @RequestParam String path) {
        return "redirect:" + domain + "/" + path;
    }
}