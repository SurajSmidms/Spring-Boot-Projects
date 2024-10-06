package com.SpringSecurity.SpringSecurity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

public interface UserService {

    public UserDetailsService userDetailsService();

}
