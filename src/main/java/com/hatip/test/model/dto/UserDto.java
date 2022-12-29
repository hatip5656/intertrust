package com.hatip.test.model.dto;

import lombok.Data;

@Data
public class UserDto {
    Long id;
    String username;
    String email;
    String password;
}
