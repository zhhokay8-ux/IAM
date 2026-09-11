package com.example.iam.user.web;

import com.example.iam.user.dto.CreateUserRequest;
import com.example.iam.user.dto.IdentityMappingRequest;
import com.example.iam.user.dto.IdentityMappingResponse;
import com.example.iam.user.dto.UpdateUserRequest;
import com.example.iam.user.dto.UserResponse;
import com.example.iam.user.service.IamIdentityMappingService;
import com.example.iam.user.service.IamUserService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class IamUserController {

    private final IamUserService userService;
    private final IamIdentityMappingService identityMappingService;

    public IamUserController(IamUserService userService, IamIdentityMappingService identityMappingService) {
        this.userService = userService;
        this.identityMappingService = identityMappingService;
    }

    @GetMapping("/{subjectId}")
    public UserResponse get(@PathVariable UUID subjectId) {
        return userService.get(subjectId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse create(@RequestBody CreateUserRequest request) {
        return userService.create(request);
    }

    @PutMapping("/{subjectId}")
    public UserResponse update(@PathVariable UUID subjectId, @RequestBody UpdateUserRequest request) {
        return userService.update(subjectId, request);
    }

    @PostMapping("/{subjectId}/identity-mappings")
    @ResponseStatus(HttpStatus.CREATED)
    public IdentityMappingResponse createMapping(
            @PathVariable UUID subjectId, @RequestBody IdentityMappingRequest request) {
        return identityMappingService.create(subjectId, request);
    }

    @GetMapping("/{subjectId}/identity-mappings")
    public List<IdentityMappingResponse> listMappings(@PathVariable UUID subjectId) {
        return identityMappingService.list(subjectId);
    }
}
