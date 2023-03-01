package com.zero.security.auth;

import com.zero.security.config.JWTService;
import com.zero.security.user.Role;
import com.zero.security.user.User;
import com.zero.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request){
        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(this.passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        this.userRepository.save(user);
        String jwtToken = this.jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = this.userRepository.findByEmail(request.getEmail()).orElseThrow();
        String jwtToken = this.jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
