package com.ddevrang.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.ddevrang.jwt.config.auth.PrincipalDetails;
import com.ddevrang.jwt.model.User;
import com.ddevrang.jwt.repository.UserRepository;

// 시큐리티가 filter를 가지고 있는데, 그 필터중 BasicAuthenticationFilter라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때, 위의 필터를 무조건 타게 되어있음.
// 만약 권한이나 인증이 필요한 주소가 아니라면 위의 필터를 타지 않음.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	// 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 된다.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("인증이나 권한이 필요한 주소가 요청됨");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader : "+jwtHeader);
		
		// header가 있는지, 정상적인지 확인
		if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);		// 다시 필터를 타도록 함
			return;
		}
		
		// JWT 토큰을 검증해서 정상적인 사용자인지 확인
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");	// Bearer(+공백)을 공백으로 치환함
		
		String username =
				JWT.require(Algorithm.HMAC512("ddevrang")).build().verify(jwtToken).getClaim("username").asString();
		
		// 서명이 정상적으로 된 경우
		if (username != null) {
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			// JWT 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다. (비밀번호는 그냥 null 처리해도 된다.)
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			
			// 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);		// 다시 필터를 타도록 함
		}
	}
}
