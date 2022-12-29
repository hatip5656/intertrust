package com.hatip.test.mapper;

import java.util.List;

public interface BaseMapper<Entity,DTO> {

    DTO toDTO(Entity entityObject);

    List<DTO> toListDTO(List<Entity> entities);

    Entity toDomainObject(DTO dto);

    List<Entity> toListDomainObject(List<DTO> dtoList);
}
