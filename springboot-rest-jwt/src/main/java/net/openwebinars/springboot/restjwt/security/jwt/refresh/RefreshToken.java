package net.openwebinars.springboot.restjwt.security.jwt.refresh;

import jakarta.persistence.*;
import lombok.*;
import net.openwebinars.springboot.restjwt.user.model.User;
import org.hibernate.annotations.NaturalId;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

@Entity
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    @Id
    private UUID id;

    //Cada usuario solo puede tener un refresh token
    //MapsId sirve para sincronizar el valor del id de esta clase
    //con el valor de la asociacion con user
    //para que el valor de las dos claves primarias
    //sea el mismo
    @MapsId
    @OneToOne
    @JoinColumn(name = "user_id", columnDefinition = "uuid")
    private User user;

    @NaturalId
    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;

    @CreatedDate
    private Instant createdAt;

}
