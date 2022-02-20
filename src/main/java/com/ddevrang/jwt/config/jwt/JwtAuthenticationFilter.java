package com.ddevrang.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.ddevrang.jwt.config.auth.PrincipalDetails;
import com.ddevrang.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음.
//  /login 요청해서 username과 password를 POST로 전송하면
// UsernamePasswordAuthenticationFilter가 동작한다.
// 그러나 현재는 시큐리티 설정에 폼로그인을 사용하지 않도록 처리하였기 때문에 동작하지 않음.
// 별도로 JwtAuthenticationFilter를 다시 시큐리티 설정에 등록해줘야 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도 중");
		
		// 1. username과 password를 받아서 정상인지 로그인 시도를 해본다.
		// 2. 받아온 authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출된다.
		// 3. 그럼 loadUserByUsername이 자동으로 실행된다.
		// 4. 리턴 값인 PrincipalDetails를 세션에 담는다.
		//    => JWT를 사용함에도 굳이 세션에 담는 이유는 권한관리를 하기 위함.
		//         권한관리를 따로 안할거면 세션을 굳이 만들 필요 없음.
		// 5. JWT 토큰을 만들어서 응답 해준다.

		try {
//			BufferedReader bReader = request.getReader();
//			
//			String input = null;
//			while ((input = bReader.readLine()) != null) {
//				System.out.println(input);
//			}
			
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
			Authentication authentication =
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 : "+principalDetails.getUser().getUsername());
			
			// return될 때 authentication 객체가 session 영역에 저장됨. => 로그인이 되었다는 뜻.
			// (JWT를 사용함에도) 굳이 세션을 만드는 이유는 권한처리를 security가 대신하도록 하기위함. (편리하므로)
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT를 response 해주면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 의미");
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// RSA방식은 아니고, Hash암호 방식
		String jwtToken = JWT.create()
				.withSubject("ddevrang토큰")		// 토큰 이름
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))			// 만료 시간. 다른 사람에게 탈취되어도 위험이 덜하도록 짧게 줌
				.withClaim("id", principalDetails.getUser().getId())											// 비공개 클레임 (키, 밸류)
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("ddevrang"));		// HMAC 방식은 시크릿키를 가지고 있어야 함.
		
		response.addHeader("Authorization", "Bearer "+jwtToken);		// 반드시 Bearer 뒤에 한칸을 띄워야 함.
	}
	
}
