package com.dto.way.gateway.filter;

import com.dto.way.gateway.utils.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {


    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {

    }


    @Override
    public GatewayFilter apply(AuthorizationHeaderFilter.Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();


            /**
             * 필터를 거치지 않아도 되는 Url이 있다면 추가
             */
//            String requestUrl = exchange.getRequest().getPath().toString();
//            if ({여기에 url을 추가}){
//                return chain.filter(exchange);
//            }


            // 요청 헤더에 "Authorization" 헤더가 포함되어 있는지 확인한다.
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                // "Authorization" 헤더가 없는 경우, UNAUTHORIZED(401) 상태로 에러 응답을 반환.
                return onError(exchange, "No Authorization header", HttpStatus.UNAUTHORIZED);
            }

            // "Authorization" 헤더에서 JWT 토큰을 추출.
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer", "");

            // 추출한 JWT 토큰의 유효성을 확인.
            if (!jwtTokenProvider.validateToken(jwt).isValid()) {
                return onError(exchange, "JWT Token is not valid", HttpStatus.UNAUTHORIZED);
            }


            // JWT 토큰이 유효한 경우, 다음 필터로 요청을 전달.
            return chain.filter(exchange);

        });
    }

    // Mono, Flux -> Spring WebFlux (기존의 SpringMVC 방식이 아니기때문에 Servlet 을 사용하지 않음)
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();
    }
}