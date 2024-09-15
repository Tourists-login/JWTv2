package com.example.secure.SecurityController;

import com.example.secure.SecurityModel.Users;
import com.example.secure.SecurityService.UserService;
import org.apache.tomcat.util.http.parser.Authorization;
//import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    UserService userService;


    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Users user){
        try {
            userService.register(user);
            return ResponseEntity.status(HttpStatus.ACCEPTED).body("User registered successfully");
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Users user){
        try {
            String s = userService.verifyLogin(user);
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(s);
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    @PostMapping("/info")
    public String info(Authentication authentication){
        Users user = userService.info(authentication);
        String userInfo = "username : " + user.getUsername() + "\n" + "email :" + user.getEmail();
        return userInfo;
    }
    @PostMapping("/Refresh")
    public String Refresh(Authentication authentication){
        String accessToken = userService.Refresh(authentication);
        return accessToken;
    }
    @PostMapping("/signout")
    public ResponseEntity<String> logout(Authentication authentication){
        String s = userService.logout(authentication);
        return ResponseEntity.ok(s);
    }

}
