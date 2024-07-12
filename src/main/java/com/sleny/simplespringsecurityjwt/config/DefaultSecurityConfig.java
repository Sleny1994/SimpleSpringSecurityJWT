package com.sleny.simplespringsecurityjwt.config;

import com.sleny.simplespringsecurityjwt.common.MyAccessDeniedHandler;
import com.sleny.simplespringsecurityjwt.common.MyAuthenticationEntryPoint;
import com.sleny.simplespringsecurityjwt.jwt.JWTFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

// 第一次访问登录验证完成后，服务端会分配给用户一个会话ID，存储在Cookies中的JSESSIONID中

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

        // 当添加了SecurityFilterChain时，则必须显示的启用接口保护和表单登录
        // 所有请求都需要权限认证
        // httpSecurity.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

        // 自定义权限认证
        httpSecurity
                // 使用JWT认证，可以关闭csrf保护
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/","/login").permitAll() // 公共接口，无权限验证
                    .requestMatchers("/needadmin").hasAuthority("ADMIN") // 需要ADMIN权限
                    .anyRequest().authenticated())
                // 在过滤器中添加JWTFilter
                .addFilterBefore(new JWTFilter(), LogoutFilter.class)
                // 开启跨域访问
                .cors(AbstractHttpConfigurer::disable)
                // 两个异常处理：未登录 和 未授权
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
                        .accessDeniedHandler(new MyAccessDeniedHandler())); // 其它所有接口都需要登录认证

        // 允许所有请求，即所有请求全部放行
        // httpSecurity.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());

        // 注释或删除下列代码，启用自定义登录接口
        // 当配置了SecurityFilterChain后，默认的formLogin是关闭的
        // httpSecurity.formLogin(Customizer.withDefaults());
        // httpSecurity.formLogin(form -> form.loginPage("/login").permitAll());
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder getBCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
