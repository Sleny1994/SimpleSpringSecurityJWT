package com.sleny.simplespringsecurityjwt.service;

import jakarta.annotation.PostConstruct;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> userDetailsMap = new HashMap<>();

    /**
     * init()方法是Spring容器初始化的核心方法
     * 会扫描所有的Bean定义
     * 并调用所有的构造函数、init方法、@PostConstruct注解的方法
     * 构建模拟用户便于测试
     * 实际生产中需要将该方法注释或删除
     */
    @PostConstruct
    public void init(){

        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        UserDetails admin = User.withUsername("admin").password(passwordEncoder.encode("admin")).authorities("ADMIN").build();
        UserDetails user = User.withUsername("user").password(passwordEncoder.encode("user")).authorities("USER").build();

        // put模拟数据时，Key的内容就填写username
        userDetailsMap.put("admin", admin);
        userDetailsMap.put("user", user);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{

        // 从创建的userDetailsMap中查找用户
        // get查询的是HashMap中的Key
        // 实际情况应该从数据库中查询用户
        UserDetails userDetails = userDetailsMap.get(username);
        if(userDetails == null){
            throw new UsernameNotFoundException(username);
        }

        return userDetails;
    }
}
