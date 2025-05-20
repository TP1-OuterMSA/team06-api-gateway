package com.example.team06apigateway.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    @Bean
    public JwtAuthenticationGatewayFilterFactory jwtAuthenticationFilter() {
        return new JwtAuthenticationGatewayFilterFactory();
    }
}
