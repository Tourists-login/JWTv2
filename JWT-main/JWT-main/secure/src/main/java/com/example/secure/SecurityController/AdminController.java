package com.example.secure.SecurityController;


import com.example.secure.SecurityModel.Users;
import com.example.secure.SecurityService.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AdminController {

    @Autowired
    UserService userService;

    @GetMapping("/all")
    public List<Users> getAllRegisterdUsers(){
        return userService.getAllRegisterdUsers();
    }

}
