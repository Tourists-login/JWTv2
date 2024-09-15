package com.example.secure.SecurityService;

import com.example.secure.SecurityModel.Users;
import com.example.secure.SecurityRepo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    @Autowired
     UserRepo repo;

    @Autowired
     AuthenticationManager authenticationManager;

    @Autowired
     JwtService jwtService;


    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);

    public Users register(Users user) {
        if (user.getUsername() == null || user.getPassword() == null || user.getEmail() == null) {
            throw new UsernameNotFoundException("Insert all information ");
        } else {
            Users newUser = repo.findByUsername(user.getUsername());
            if (newUser != null) {
                throw new UsernameNotFoundException("User with username " + user.getUsername() + " already exists");
            }
            user.setPassword(encoder.encode(user.getPassword()));
            return repo.save(user);
        }
    }

    public List<Users> getAllRegisterdUsers(){
        return repo.findAll();
    }

    public String verifyLogin(Users user){
        long accessTime = (long) (15 * 60 * 1000L); // 15Min
        long refreshTime = (long) (1440L * 30 * 60 * 1000L); // 30Dayes

        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));

        if (authentication.isAuthenticated()){
            String tokens = "Access : "+jwtService.generateToken(user.getUsername(),"access",accessTime)+"\n";
            tokens+= "Refresh : "+jwtService.generateToken(user.getUsername(),"refresh",refreshTime);
            Users user1 = repo.findByUsername(user.getUsername());
            user1.setEnabled(true);
            repo.save(user1);
            return tokens;
        }
        throw new UsernameNotFoundException("Invalid username or password");
    }

    public Users info(Authentication authentication){
        Users user = repo.findByUsername(authentication.getName());
        return user;
    }

    public String Refresh(Authentication authentication) {
        Users user = repo.findByUsername(authentication.getName());
        long accessTime = (long) (15 * 60 * 1000L);
        String tokens = "Access : "+jwtService.generateToken(user.getUsername(),"access",accessTime);
        return tokens;
    }

    public String logout(Authentication authentication) {
        Users user = repo.findByUsername(authentication.getName());
        user.setEnabled(false);
        repo.save(user);
        return "You have been logged out successfully";
    }
}

/*






 */