package com.SpringSecurity.SpringSecurity.DTO;

import lombok.Data;

@Data
public class SignInRequest {

    private String email;
    private String password;

}
