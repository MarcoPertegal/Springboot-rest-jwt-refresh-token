package net.openwebinars.springboot.restjwt.security.jwt.refresh;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import net.openwebinars.springboot.restjwt.user.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    //en este servicio antendemos a las consultas del
    //repositorio del refresh token
    //tambien se crea el token de refresco y se verifica

    private final RefreshTokenRepository refreshTokenRepository;

    //esto se llama desde el application properties
    @Value("${jwt.refresh.duration}")
    private int durationInMinutes;

    public Optional<RefreshToken> findByToken(String token){
        return refreshTokenRepository.findByToken(token);
    }

    //sirve para que esta peticion no pueda modificarse y que se haga en el marco de una transacción
    @Transactional
    public int deleteByUser(User user){
        return refreshTokenRepository.deleteByUser(user);
    }

    //creamos el token del usuario
    public RefreshToken createRefreshToken(User user){
        RefreshToken refreshToken = new RefreshToken();
        //aqui se crea se setea un uuid aleatorio y un fecha de expiración basandonos en el applicationproperties
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusSeconds(durationInMinutes * 60));

        refreshToken = refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    //verificar el token
    public RefreshToken verify(RefreshToken refreshToken){
        //comparamos la fecha de expiracion del token con la fecha actual
        //compareTo devuelve entero.  Devuelve un número negativo si el objeto actual es menor que el objeto pasado como argumento
        //si son iguales devuelve 0 y si el segundo es mayor devuelve un entero superior a 0
        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0){
            //Token ha caducado
            refreshTokenRepository.delete(refreshToken);
            throw new RefreshTokenException("Expired refresh token:"+ refreshToken.getToken() + "Please, login again");
        }
        return refreshToken;
    }
}
