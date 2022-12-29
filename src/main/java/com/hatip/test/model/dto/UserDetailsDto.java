package com.hatip.test.model.dto;

import lombok.Data;

@Data
public class UserDetailsDto {
    Long id;
    UserDto user;
    String name;
    String billingAddress;
    String shippingAddress;
}
