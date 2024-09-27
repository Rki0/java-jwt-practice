package com.jwtTutorial_yumi.jwtTutorial_yumi.config;

import com.jwtTutorial_yumi.jwtTutorial_yumi.jwt.JWTFilter;
import com.jwtTutorial_yumi.jwtTutorial_yumi.jwt.JWTUtil;
import com.jwtTutorial_yumi.jwtTutorial_yumi.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration // 이 클래스가 configuration으로 관리되어야함을 알리는 어노테이션
@EnableWebSecurity // Security 관련 코드이므로
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 비밀번호를 암호화하기 위한 기능
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CORS 설정
        http.cors((cors) -> cors.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration corsConfiguration = new CorsConfiguration();

                corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); // 프론트 서버 허용
                corsConfiguration.setAllowedMethods(Collections.singletonList("*")); // 허용할 Method(Get, Post, etc..)
                corsConfiguration.setAllowCredentials(true); // 프론트 쪽에서 credential 설정을 true로 하면, 여기도 true로 해줘야함.
                corsConfiguration.setAllowedHeaders(Collections.singletonList("*")); // 허용할 헤더
                corsConfiguration.setMaxAge(3600L); // 허용을 유지할 시간
                corsConfiguration.setExposedHeaders(Collections.singletonList("Authorization")); // Authorization 헤더 허용

                return corsConfiguration;
            }
        }));

        // csrf disable
        // JWT 방식은 세션을 stateless 상태로 관리하기 때문에 CSRF 방어를 하지 않아도 된다.
        http.csrf((auth) -> auth.disable());

        // Form 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http.httpBasic((auth) -> auth.disable());

        // 경로 별 인가 작업
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll() // 모든 사용자에게 허용
                .requestMatchers("/admin").hasRole("ADMIN") // /admin 경로 요청은 ADMIN인 사람만 접근 가능하고
                .anyRequest().authenticated()); // 그 외에는 로그인한 사람들만 접근 가능하다(authenticated)

        // 커스텀 JWTFilter 등록
        // LoginFilter 앞에 등록!
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 커스텀 LoginFilter 등록
        // UsernamePasswordAuthenticationFilter 자리에 LoginFilter를 추가하겠다.
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정 : JWT는 stateless하게 관리한다.(매우 중요!!)
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
