package com.hatip.test.service;

import com.hatip.test.mapper.UserMapper;
import com.hatip.test.model.dto.UserDto;
import com.hatip.test.model.entity.UserEntity;
import com.hatip.test.repository.UserRepo;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;
    private final UserMapper mapper;

    public List<UserDto> getAll() {
        return mapper.toListDTO(userRepo.findAll());
    }

    public UserDto getOne(Long id) {
        Optional<UserEntity> user = userRepo.findById(id);
        if (user.isPresent()) {
            return mapper.toDTO(user.get());
        } else {
            throw new NoSuchElementException("There is no User with ID:" + id);
        }
    }

    public UserDto save(UserDto user) {
        return mapper.toDTO(userRepo.save(mapper.toDomainObject(user)));
    }

    public void delete(Long id) {
        userRepo.deleteById(id);
    }
}
