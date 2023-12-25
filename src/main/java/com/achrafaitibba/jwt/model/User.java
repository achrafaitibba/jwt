package com.achrafaitibba.jwt.model;

import com.achrafaitibba.jwt.configuration.token.Token;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Builder
public class User implements UserDetails {

    @Id
    private String username;
    private String password;
    @JsonIgnore
    @OneToMany(mappedBy = "user")
    private List<Token> tokens;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        System.out.println("xxxxxxxxxxxxxxxxxxx User().getPassword xxxxxxxxxxxxxxxxxxxxx 1\n");
        return password;
    }

    @Override
    public String getUsername() {
        System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxx User().getUsername xxxxxxxxxxxxxxxxxxxxxxxx 2\n");
        return username;
    }

    //todo understand this one and all the methods below
    // It gives forbidden if set to false when authenticating
    @Override
    public boolean isAccountNonExpired() {
        System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxx User().isAccountNonExpired xxxxxxxxxxxxxxxxxxxxxxxx 3\n");

        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        System.out.println("xxxxxxxxxxxxxxxxxxxxxxxx User().isAccountNonLocked xxxxxxxxxxxxxxxxxxxxxxxxxxx 4\n");
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        System.out.println("xxxxxxxxxxxxxxxxxxxxxxxx User().isCredentialsNonExpired xxxxxxxxxxxxxxxxxxxxxxxxxxx 5\n");

        return true;
    }

    @Override
    public boolean isEnabled() {
        System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxx User().isEnabled xxxxxxxxxxxxxxxxxxxxxxxx 6\n");

        return true;
    }

}
