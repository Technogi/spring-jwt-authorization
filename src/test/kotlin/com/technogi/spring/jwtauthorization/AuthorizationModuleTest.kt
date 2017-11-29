package com.technogi.spring.jwtauthorization

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status


@RunWith(SpringRunner::class)
@SpringBootTest(
  webEnvironment = RANDOM_PORT,
  classes = arrayOf(JwtAuthorizationApplication::class)
)
@AutoConfigureMockMvc(secure = true)
class AuthorizationModuleTest {


    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun test_permit_all() {
        mockMvc.perform(get("/"))
          .andExpect { status().is2xxSuccessful }
          .andExpect { content().string("Hello World") }
    }

    @Test
    fun test_unauthorized_request_to_secured_content() {

        val token = Jwts.builder()
          .setSubject("Joe")
          .setClaims(mapOf("rfc" to "hemc809023ert", "policy" to "123457", "roles" to arrayOf("NOADMIN")))
          .signWith(SignatureAlgorithm.HS512, SecurityConfiguration.secConfig.jwt?.secret?.toByteArray())
          .compact()


        mockMvc.perform(get("/secured").header(SecurityConfiguration.secConfig.jwt?.header,"bearer $token"))
          .andExpect { status().isUnauthorized }

    }

    @Test
    fun test_authorized_request_to_unauthorized_content() {
        mockMvc.perform(get("/forbidden"))
          .andExpect { status().isUnauthorized }

    }

    @Test
    fun test_authorized_request_to_secured_content() {

        val token = Jwts.builder()
          .setSubject("Joe")
          .setClaims(mapOf("rfc" to "hemc809023ert", "policy" to "123457"))
          .signWith(SignatureAlgorithm.HS512, SecurityConfiguration.secConfig.jwt?.secret?.toByteArray())
          .compact()
        mockMvc.perform(get("/secured").header(SecurityConfiguration.secConfig.jwt?.header,"bearer $token"))
          .andExpect { status().is2xxSuccessful }
          .andExpect { content().string("Secured") }

    }

    @Test
    fun test_authorized_unpriviledged_request_to_role_protected_content() {

        val token = Jwts.builder()
          .setSubject("Joe")
          .setClaims(mapOf("rfc" to "hemc809023ert", "policy" to "123457"))
          .signWith(SignatureAlgorithm.HS512, SecurityConfiguration.secConfig.jwt?.secret?.toByteArray())
          .compact()
        mockMvc.perform(get("/secured").header(SecurityConfiguration.secConfig.jwt?.header,"bearer $token"))
          .andExpect { status().isUnauthorized }

    }

    @Test
    fun test_authorized_with_incorrect_priviledges_request_to_role_protected_content() {

        val token = Jwts.builder()
          .setSubject("Joe")
          .setClaims(mapOf("rfc" to "hemc809023ert", "policy" to "123457", "roles" to arrayOf("NOADMIN")))
          .signWith(SignatureAlgorithm.HS512, SecurityConfiguration.secConfig.jwt?.secret?.toByteArray())
          .compact()
        mockMvc.perform(get("/requires-role").header(SecurityConfiguration.secConfig.jwt?.header,"bearer $token"))
          .andExpect { status().isUnauthorized }

    }

    @Test
    fun test_authorized_with_correct_priviledges_request_to_role_protected_content() {

        val token = Jwts.builder()
          .setSubject("Joe")
          .setClaims(mapOf("rfc" to "hemc809023ert", "policy" to "123457", "roles" to arrayOf("ADMIN")))
          .signWith(SignatureAlgorithm.HS512, SecurityConfiguration.secConfig.jwt?.secret?.toByteArray())
          .compact()
        println(token)
        mockMvc.perform(get("/secured").header(SecurityConfiguration.secConfig.jwt?.header,"bearer $token"))
          .andExpect { status().is2xxSuccessful }
          .andExpect { content().string("Responded with role") }

    }

    @Test
    fun test_invalid_token() {

        val token = "344"+Jwts.builder()
          .setSubject("Joe")
          .setClaims(mapOf("rfc" to "hemc809023ert", "policy" to "123457", "roles" to arrayOf("ADMIN")))
          .signWith(SignatureAlgorithm.HS512, SecurityConfiguration.secConfig.jwt?.secret?.toByteArray())
          .compact()+"344"
        mockMvc.perform(get("/secured").header(SecurityConfiguration.secConfig.jwt?.header,"bearer $token"))
          .andExpect { status().isForbidden }

    }
}