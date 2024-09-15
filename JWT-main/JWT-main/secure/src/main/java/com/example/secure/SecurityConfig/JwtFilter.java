package com.example.secure.SecurityConfig;

import com.example.secure.SecurityModel.Users;
import com.example.secure.SecurityRepo.UserRepo;
import com.example.secure.SecurityService.JwtService;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;



@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserRepo userRepo;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException, java.io.IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        boolean enabled1 = false;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUserName(token);
            Users user = userRepo.findByUsername(username);
            enabled1 = user.isEnabled();
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null && enabled1) {

            String tokenType = jwtService.extractTokenType(token);

            if ("access".equals(tokenType)) {
                if (jwtService.validateToken(token, username)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, null, null);
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } else{
                if (!jwtService.validateToken(token, username)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Both access and refresh tokens expired. Please log in again.");
                } else {
                    Long accessTime = (long)15 * 60 * 1000L;
                    String newAccessToken = jwtService.generateToken(username,"access",accessTime);
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType("application/json");
                    response.getWriter().write("{ \"accessToken\": \"" + newAccessToken + "\" }");
                }
                return ;
            }
        }

        filterChain.doFilter(request, response);
    }

}
