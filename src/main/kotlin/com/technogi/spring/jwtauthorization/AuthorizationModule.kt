package com.technogi.spring.jwtauthorization

import io.jsonwebtoken.*
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.web.filter.OncePerRequestFilter
import java.lang.Exception
import java.security.SignatureException
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


abstract class AuthorizationModule() : WebSecurityConfigurerAdapter() {
    abstract fun deserializeToken(claims: Claims): JwtAuthenticationToken
    @Throws(Exception::class)
    abstract fun config(httpSecurity: HttpSecurity?)

    abstract fun getConfig(): SecurityConfig

    override final fun configure(http: HttpSecurity?) {

        http!!
          .csrf().disable().headers()
          .frameOptions().disable()
          .and()

          .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        config(http)

        http
          .addFilterBefore(
            JWTAuthenticationTokenFilter(getConfig(), this::deserializeToken),
            UsernamePasswordAuthenticationFilter::class.java)
          .headers().cacheControl()
    }
}

class JWTAuthenticationTokenFilter(val config: SecurityConfig, val jwtParseFunc: (Claims) -> JwtAuthenticationToken) : OncePerRequestFilter() {

    val log = LoggerFactory.getLogger(this.javaClass)
    override fun doFilterInternal(request: HttpServletRequest?, response: HttpServletResponse?, filterChain: FilterChain?) {
        log.trace("Validating user")
        val authHeader = request?.getHeader(this.config.jwt?.header)
        log.trace("Got header {}", authHeader)
        if (authHeader != null && authHeader.length >= 7) {
            val authToken = authHeader.substring(7)
            log.debug("Parsing token {}", authToken)
            try {
                val authentication = parseToken(authToken)
                authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = authentication
            } catch (e: SignatureException) {
                log.info("Invalid JWT signature.")
                log.trace("Invalid JWT signature trace: {}", e)
            } catch (e: MalformedJwtException) {
                log.info("Invalid JWT token.")
                log.trace("Invalid JWT token trace: {}", e)
            } catch (e: ExpiredJwtException) {
                log.info("Expired JWT token.")
                log.trace("Expired JWT token trace: {}", e)
            } catch (e: UnsupportedJwtException) {
                log.info("Unsupported JWT token.")
                log.trace("Unsupported JWT token trace: {}", e)
            } catch (e: IllegalArgumentException) {
                log.info("JWT token compact of handler are invalid.")
                log.trace("JWT token compact of handler are invalid trace: {}", e)
            }

        }
        filterChain?.doFilter(request, response)
    }

    private fun parseToken(token: String): JwtAuthenticationToken {
        val claims = Jwts.parser()
          .setSigningKey(config.jwt?.secret?.toByteArray())
          .parseClaimsJws(token)
          .getBody()
        log.trace("Decoded claims {}", claims)

        return jwtParseFunc(claims)
    }

}

abstract class JwtAuthenticationToken(userDetails: JwtUserDetails) : UsernamePasswordAuthenticationToken(userDetails, null) {

}


open class JwtUserDetails(val claims: Claims) : UserDetails {
    override fun getAuthorities() =
      claims.get("roles", Array<String>::class.java).map { GrantedAuthority { it } }.toMutableList()


    override fun isEnabled() = true
    override fun getUsername() = claims.subject
    override fun isCredentialsNonExpired() = claims.expiration.before(Date())
    override fun getPassword(): String {
        throw NotImplementedError()
    }

    override fun isAccountNonExpired() = true
    override fun isAccountNonLocked() = true

}

data class JWTConfig(var secret: String?, var header: String?) {
    constructor() : this(null, null) {}
}

data class SecurityConfig(var jwt: JWTConfig?) {
    constructor() : this(null) {}
}