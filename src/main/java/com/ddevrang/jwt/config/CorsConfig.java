package com.ddevrang.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      
      System.out.println("cors");
      
      config.setAllowCredentials(true);	// 내 서버가 응답을 할 때 JSON을 자바스크립트에서 처리할 수 있도록 할지를 설정하는 
      config.addAllowedOrigin("*"); 		// 모든 ip에 응답을 허용
      config.addAllowedHeader("*");		// 모든 header에 응답을 허용
      config.addAllowedMethod("*");		// 모든 post, get, delete, patch 요청을 허용

      source.registerCorsConfiguration("/api/**", config);	// 해당 주소에 대한 모든 접근은 config 설정을 따르게 함.
      return new CorsFilter(source);
   }

}