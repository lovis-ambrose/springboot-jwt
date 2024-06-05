package com.security.JWT.auth;

import com.security.JWT.repository.UserRepository;
import com.security.JWT.service.JwtService;
import com.security.JWT.user.Role;
import com.security.JWT.user.User;
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
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) //need to encode the password (need password encoder)
                .role(Role.USER)    //make a static role USER
                .build();
        userRepository.save(user);
        //to return user response with token
        var jwtToken = jwtService.extractToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //executed if username and password are correct
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        //generate token and send it back
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(); //throw any exception (specify, try and catch it)
        var jwtToken = jwtService.extractToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
