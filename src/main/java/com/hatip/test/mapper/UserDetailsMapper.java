package com.hatip.test.mapper;

import com.hatip.test.model.dto.UserDetailsDto;
import com.hatip.test.model.entity.UserDetailsEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring",uses = UserMapper.class)
public interface UserDetailsMapper extends BaseMapper<UserDetailsEntity, UserDetailsDto> {
}
