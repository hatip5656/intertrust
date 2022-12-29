package com.hatip.test.controller;

import com.hatip.test.model.dto.UserDetailsDto;
import com.hatip.test.service.UserDetailsService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user-details")
@RequiredArgsConstructor
public class UserDetailsController {
    private final UserDetailsService service;

    @GetMapping
    public ResponseEntity<List<UserDetailsDto>> getUsers() {
        return ResponseEntity.ok(service.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDetailsDto> get(@PathVariable("id") Long id) {
        return ResponseEntity.ok(service.getOne(id));
    }
    @GetMapping("/by-user/{id}")
    public ResponseEntity<UserDetailsDto> getByUser(@PathVariable("id") Long id) {
        return ResponseEntity.ok(service.getByUserID(id));
    }
    @PostMapping
    public ResponseEntity<UserDetailsDto> save(@RequestBody UserDetailsDto user) {
        try {
            return ResponseEntity.ok(service.save(user));
        } catch (Exception e) {
            return ResponseEntity.unprocessableEntity().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity delete(@PathVariable("id") Long id) {
        try {
            service.delete(id);
            return (ResponseEntity) ResponseEntity.ok();
        } catch (Exception e) {
            return ResponseEntity.noContent().build();
        }

    }
}
