package com.jwtTutorial_yumi.jwtTutorial_yumi.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        corsRegistry.addMapping("/**") // 모든 Controller 경로에 대해서
                .allowedOrigins("http://localhost:3000"); // 프론트 주소를 허가한다.
    }
}
