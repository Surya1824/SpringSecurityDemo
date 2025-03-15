package com.surya.SpringSecurityDemo.service;

import com.surya.SpringSecurityDemo.Model.User;
import com.surya.SpringSecurityDemo.Model.UserPrinciples;
import com.surya.SpringSecurityDemo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private final Logger logger = LoggerFactory.getLogger(MyUserDetailsService.class);

    @Autowired
    private UserRepository userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByUsername(username);
        if(user == null){
            logger.info("404 User Name Not Found");
            throw new UsernameNotFoundException("404 User Name Not Found");
        }
        return new UserPrinciples(user);
//        return getUserDetails(user);
    }

    private UserDetails getUserDetails(User user){

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword()) // Ensure this matches stored password
                .roles("User")
                .build();
    }
}
