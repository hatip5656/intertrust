package com.hatip.test.service;

import com.hatip.test.mapper.UserDetailsMapper;
import com.hatip.test.model.dto.UserDetailsDto;
import com.hatip.test.model.entity.UserDetailsEntity;
import com.hatip.test.repository.UserDetailsRepo;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsService {
    private final UserDetailsRepo userDetailsRepo;
    private final UserDetailsMapper mapper;

    public List<UserDetailsDto> getAll() {
        return mapper.toListDTO(userDetailsRepo.findAll());
    }

    public UserDetailsDto getOne(Long id) {
        Optional<UserDetailsEntity> details = userDetailsRepo.findById(id);
        if (details.isPresent()) {
            return mapper.toDTO(details.get());
        } else {
            throw new NoSuchElementException("There is no UserDetails with ID:" + id);
        }
    }

    public UserDetailsDto save(UserDetailsDto userDetails) {
        return mapper.toDTO(userDetailsRepo.save(mapper.toDomainObject(userDetails)));
    }

    public void delete(Long id) {
        userDetailsRepo.deleteById(id);
    }

    public UserDetailsDto getByUserID(Long id) {
        UserDetailsEntity details = userDetailsRepo.findByUserId(id);
            return mapper.toDTO(details);
    }
}
