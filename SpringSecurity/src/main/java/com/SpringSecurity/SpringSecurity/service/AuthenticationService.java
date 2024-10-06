package com.SpringSecurity.SpringSecurity.service;

import com.SpringSecurity.SpringSecurity.DTO.JwtAuthenticationResponse;
import com.SpringSecurity.SpringSecurity.DTO.RefreshTokenRequest;
import com.SpringSecurity.SpringSecurity.DTO.SignInRequest;
import com.SpringSecurity.SpringSecurity.DTO.SignUpRequest;
import com.SpringSecurity.SpringSecurity.entities.User;

public interface AuthenticationService {

    User signUp(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signIn(SignInRequest signInRequest);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
