package com.example.iam.token.signing;

import com.example.iam.token.entity.IamSigningKeyEntity;
import com.example.iam.token.repository.IamSigningKeyRepository;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;

public final class InMemorySigningKeyRepository implements IamSigningKeyRepository {

    private final List<IamSigningKeyEntity> store = new CopyOnWriteArrayList<>();

    @Override
    public Optional<IamSigningKeyEntity> findByKid(String kid) {
        return store.stream().filter(entity -> entity.getKid().equals(kid)).findFirst();
    }

    @Override
    public List<IamSigningKeyEntity> findByStatus(String status) {
        return store.stream().filter(entity -> status.equals(entity.getStatus())).toList();
    }

    @Override
    public List<IamSigningKeyEntity> findByStatusIn(Collection<String> statuses) {
        return store.stream().filter(entity -> statuses.contains(entity.getStatus())).toList();
    }

    @Override
    public Optional<IamSigningKeyEntity> findFirstByStatusOrderByActivatedAtDesc(String status) {
        return store.stream()
                .filter(entity -> status.equals(entity.getStatus()))
                .max(Comparator.comparing(IamSigningKeyEntity::getActivatedAt, Comparator.nullsLast(Comparator.naturalOrder())));
    }

    @Override
    public IamSigningKeyEntity save(IamSigningKeyEntity entity) {
        if (entity.getId() == null) {
            entity.setId(UUID.randomUUID());
        }
        store.removeIf(existing -> existing.getId().equals(entity.getId()));
        store.add(entity);
        return entity;
    }

    @Override
    public <S extends IamSigningKeyEntity> List<S> saveAll(Iterable<S> entities) {
        List<S> saved = new ArrayList<>();
        entities.forEach(entity -> saved.add((S) save(entity)));
        return saved;
    }

    @Override
    public Optional<IamSigningKeyEntity> findById(UUID id) {
        return store.stream().filter(entity -> id.equals(entity.getId())).findFirst();
    }

    @Override
    public boolean existsById(UUID id) {
        return findById(id).isPresent();
    }

    @Override
    public List<IamSigningKeyEntity> findAll() {
        return List.copyOf(store);
    }

    @Override
    public List<IamSigningKeyEntity> findAllById(Iterable<UUID> ids) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long count() {
        return store.size();
    }

    @Override
    public void deleteById(UUID id) {
        store.removeIf(entity -> id.equals(entity.getId()));
    }

    @Override
    public void delete(IamSigningKeyEntity entity) {
        store.remove(entity);
    }

    @Override
    public void deleteAllById(Iterable<? extends UUID> ids) {
        ids.forEach(this::deleteById);
    }

    @Override
    public void deleteAll(Iterable<? extends IamSigningKeyEntity> entities) {
        entities.forEach(this::delete);
    }

    @Override
    public void deleteAll() {
        store.clear();
    }

    @Override
    public List<IamSigningKeyEntity> findAll(Sort sort) {
        return findAll();
    }

    @Override
    public Page<IamSigningKeyEntity> findAll(Pageable pageable) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity> S saveAndFlush(S entity) {
        return (S) save(entity);
    }

    @Override
    public <S extends IamSigningKeyEntity> List<S> saveAllAndFlush(Iterable<S> entities) {
        return saveAll(entities);
    }

    @Override
    public void flush() {
    }

    @Override
    public void deleteInBatch(Iterable<IamSigningKeyEntity> entities) {
        deleteAll(entities);
    }

    @Override
    public void deleteAllInBatch(Iterable<IamSigningKeyEntity> entities) {
        deleteAll(entities);
    }

    @Override
    public void deleteAllByIdInBatch(Iterable<UUID> ids) {
        deleteAllById(ids);
    }

    @Override
    public void deleteAllInBatch() {
        deleteAll();
    }

    @Override
    public IamSigningKeyEntity getOne(UUID id) {
        return findById(id).orElseThrow();
    }

    @Override
    public IamSigningKeyEntity getById(UUID id) {
        return getOne(id);
    }

    @Override
    public IamSigningKeyEntity getReferenceById(UUID id) {
        return getOne(id);
    }

    @Override
    public <S extends IamSigningKeyEntity> Optional<S> findOne(Example<S> example) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity> List<S> findAll(Example<S> example) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity> List<S> findAll(Example<S> example, Sort sort) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity> Page<S> findAll(Example<S> example, Pageable pageable) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity> long count(Example<S> example) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity> boolean exists(Example<S> example) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <S extends IamSigningKeyEntity, R> R findBy(
            Example<S> example, java.util.function.Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) {
        throw new UnsupportedOperationException();
    }
}
