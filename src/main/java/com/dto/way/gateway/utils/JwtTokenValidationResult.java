package com.dto.way.gateway.utils;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenValidationResult {

    private boolean isValid;
    private String errorMessage;

}
