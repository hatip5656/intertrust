package com.hatip.test.mapper;

import com.hatip.test.model.dto.UserDto;
import com.hatip.test.model.entity.UserEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper extends BaseMapper<UserEntity, UserDto> {
}
