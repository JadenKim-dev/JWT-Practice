package com.cos.jwt.config.jwt;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면(post) UsernamePasswordAuthenticationFilter 동작함
// 그러나 formLogin().disable()로 설정한 상태이기 때문에, 이 필터가 동작하지 않음
// 따라서 이 필터를 따로 추가해줘야 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    /*
    1. username, password 받아서
    2. 정상인지 로그인 시도를 해 본다
        - authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출, loadUserByUsername()이 실행됨
    3. PrincipalDetails를 세션에 담고(권한 관리를 위해서)
    4. JWT 토큰을 만들어서 응답해주면 됨
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도 중");

        // 1. username, password 받아서
        ObjectMapper om = new ObjectMapper();

        try {
            User user = om.readValue(request.getInputStream(), User.class);
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            // -> 정상적인 로그인 요청이면, 즉 DB에 있는 username과 password가 일치하면 authentication이 리턴됨
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨: " + principalDetails.getUsername());  // 출력 제대로 됨 -> 로그인 정상적으로 되었다는 뜻

            // 반환하면 authentication 객체는 session 영역에 저장됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문, 편하려고 하는 것!
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 단지 권한 처리 때문에 session에 넣어주는 것
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증이 완료되었음");
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
