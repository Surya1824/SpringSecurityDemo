package com.surya.SpringSecurityDemo.repository;


import com.surya.SpringSecurityDemo.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    public User findByUsername(String userName);

}
