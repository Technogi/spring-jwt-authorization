package com.technogi.spring.jwtauthorization

import io.jsonwebtoken.Claims
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RequestMapping
@RestController
@SpringBootApplication
class JwtAuthorizationApplication {

    @GetMapping("/")
    fun hello() = "Hello World"

    @GetMapping("/secured")
    fun secure() = "Secured"

    @GetMapping("requires-role")
    fun requiresRole() = "Responded with role"

    @GetMapping("forbidden")
    fun forbidden() = "Never gets here"
}

fun main(args: Array<String>) {
    SpringApplication.run(JwtAuthorizationApplication::class.java, *args)
}

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
class SecurityConfiguration : AuthorizationModule() {
    override fun getConfig()= SecurityConfiguration.secConfig

    companion object {
        val secConfig = SecurityConfig(JWTConfig("SUPERSECRETO", "X-AUTHME"))
    }
    override fun deserializeToken(claims: Claims): JwtAuthenticationToken {
        return TestAutheticationToken(
          TestUserDetails(claims,
            claims.get("rfc", String::class.java),
            claims.get("policy", String::class.java)))
    }

    override fun config(httpSecurity: HttpSecurity?) {
        httpSecurity!!.authorizeRequests()
          .antMatchers(HttpMethod.GET, "/").permitAll()
          .antMatchers(HttpMethod.GET, "/secured").authenticated()
          .antMatchers(HttpMethod.GET, "/requires-role").hasAnyRole("ADMIN")
          .anyRequest().denyAll()
    }

    override fun configure(web: WebSecurity?) {
        web!!.ignoring()
          .antMatchers(HttpMethod.OPTIONS, "/**")
          .antMatchers("/content/**")
          .antMatchers("/test/**")
    }

}

class TestAutheticationToken(userDetails: TestUserDetails)
    : JwtAuthenticationToken(userDetails) {

}

class TestUserDetails(claims: Claims, val rfc: String, val policy: String) : JwtUserDetails(claims) {

}


