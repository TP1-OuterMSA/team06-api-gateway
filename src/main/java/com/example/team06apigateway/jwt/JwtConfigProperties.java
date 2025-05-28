package com.example.team06apigateway.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtConfigProperties {
    private String secret;
    private ProtectedPaths protectedPaths = new ProtectedPaths();

    @Getter
    @Setter
    public static class ProtectedPaths {
        private List<String> userPaths = new ArrayList<>();
        private List<String> adminPaths = new ArrayList<>();
    }

    public List<String> getAllProtectedPaths() {
        List<String> all = new ArrayList<>();
        all.addAll(protectedPaths.getUserPaths());
        all.addAll(protectedPaths.getAdminPaths());
        return all;
    }
}
