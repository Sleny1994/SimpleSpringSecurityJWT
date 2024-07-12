package com.sleny.simplespringsecurityjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    // 公共接口均可以访问
    @GetMapping("/")
    public String index(){
        return "Hello index.";
    }

    // 需登录验证才可以访问
    @GetMapping("/needlogin")
    public String needLogin(){

        // 静态工具类获取当前的SecurityContext上下文
        SecurityContext securityContext = SecurityContextHolder.getContext();
        // 通过认证的可以获取当前用户的一些信息
        Authentication authentication = securityContext.getAuthentication();
        // 检查是否已认证
        System.out.println(authentication.isAuthenticated());  // true
        // 检查用户详情
        System.out.println(authentication.getName());     // user
        System.out.println(authentication.getAuthorities());  //[USER]

        return "Hello, you have been logon.";
    }

    // 需要具有Admin权限才可以访问
    @GetMapping("/needadmin")
    public String needAdmin(){
        return "Hello, you have admin authority.";
    }
}
