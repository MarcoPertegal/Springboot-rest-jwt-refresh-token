package net.openwebinars.springboot.restjwt.security.jwt.refresh;

import net.openwebinars.springboot.restjwt.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, User> {

    //A través del campo token vamos a buscar la entidad refresh token que tiene el usaurio

    Optional<RefreshToken> findByToken(String token);

    //Nos permite borrar un token de refresco por un usuario
    @Modifying
    int deleteByUser(User user);
}
