package com.jwtTutorial_yumi.jwtTutorial_yumi.jwt;

import com.jwtTutorial_yumi.jwtTutorial_yumi.dto.CustomUserDetails;
import com.jwtTutorial_yumi.jwtTutorial_yumi.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizaiton = request.getHeader("Authorization");

        // 토큰이 없거나, Bearer로 시작하지 않으면 메서드 종료
        if(authorizaiton == null || !authorizaiton.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response); // 이 필터를 종료하고, request와 response를 다음 필터로 넘긴다.

            return; // 메서드 종료
        }

        String token = authorizaiton.split(" ")[1]; // Bearer tokenstring에서 tokenstring을 얻는다.

        // 토큰 만료 검증
        if(jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            return; // 메서드 종료
        }

        // 토큰에서 정보 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // UserEntity 초기화
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 비밀번호는 토큰에 담긴 정보가 아니기 때문에 임의로 설정. 매번 DB 조회하면 부하가 있기 때문.
        userEntity.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // Spring Security 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
