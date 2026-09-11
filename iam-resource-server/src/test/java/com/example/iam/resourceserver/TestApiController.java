package com.example.iam.resourceserver;

import com.example.iam.resourceserver.security.RequireScope;
import com.example.iam.user.context.UserContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestApiController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "ok";
    }

    @GetMapping("/order")
    @RequireScope("order.read")
    public String orderEndpoint() {
        return UserContextHolder.get() == null ? "missing-context" : UserContextHolder.get().subjectId();
    }
}
