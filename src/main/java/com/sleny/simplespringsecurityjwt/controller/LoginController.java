package com.sleny.simplespringsecurityjwt.controller;

import com.sleny.simplespringsecurityjwt.dao.LoginRequest;
import com.sleny.simplespringsecurityjwt.jwt.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class LoginController {

    /* 无JWT认证
    protected static AuthenticationManager authenticationManager;
    protected static SecurityContextRepository securityContextRepository;

    @PostMapping("/login")
    public void login(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                      @RequestParam("username") String username,
                      @RequestParam("password") String password)
    throws IOException, ServletException {

        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        // 通过前端提交的username/password进行认证
        Authentication authentication = authenticationManager.authenticate(token);
        // 设置空的上下文
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        // 设置认证信息
        securityContext.setAuthentication(authentication);
        // 保存上下文
        securityContextRepository.saveContext(securityContext, httpServletRequest, httpServletResponse);
        // 检查是否存在之前的请求，若有则跳转，否则跳转至首页
        SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(httpServletRequest, httpServletResponse);
        if(savedRequest != null){
            String targetUrl = savedRequest.getRedirectUrl();
            httpServletResponse.sendRedirect(targetUrl);
        }else{
            httpServletResponse.sendRedirect("/");
        }
    }
     */

    // 加入JWT认证
    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest login){
        Map<String, Object> map = new HashMap<>();

        try{
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword());
            Authentication authentication = authenticationManager.authenticate(token);
            String jwt = JWTUtils.generateToken(authentication);
            map.put("jwt", jwt);
        }catch (BadCredentialsException ex){
            map.put("error", ex.getMessage());
        }
        return map;
    }
}