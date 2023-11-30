package com.example.springsecurityjwt;

import com.example.springsecurityjwt.controller.AuthenticationController;
import com.example.springsecurityjwt.dto.RegistrationDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SpringSecurityJwtApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void unauthorizedUsersCanAccessAuthURLs() throws Exception {
		this.mockMvc.perform(post("/auth/register")
				.content("{\"username\":\"joy\",\"password\":\"pass\"}")
						.contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").isNumber())
                .andExpect(jsonPath("$.username").isString())
                .andExpect(jsonPath("$.password").isString())
                .andExpect(jsonPath("$.authorities.[0 ].roleId").isNumber())
                .andExpect(jsonPath("$.authorities.[0].authority").value("USER"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.accountNonLocked").value(true))
                .andExpect(jsonPath("$.accountNonExpired").value(true))
                .andExpect(jsonPath("$.credentialsNonExpired").value(true));
	}

	@Test
	void unauthorizedUsersCannotAccessUserURls() throws Exception {
		this.mockMvc.perform(get("/user/"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void unauthorizedUsersCannotAccessAdminURls() throws Exception {
		this.mockMvc.perform(get("/admin/"))
				.andExpect(status().isUnauthorized());
	}

//	@Test
//	void userWithAdminRoleCanAccessAdminURLs() throws Exception {
//		this.mockMvc.perform(post("/auth/login")
//				.content("{\"username\":\"admin\",\"password\":\"password\"}")
//				.contentType("application/json"))
//				.andExpect(status().isOk());
//
//		this.mockMvc.perform(get("/admin/"))
//				.andExpect(status().isOk());
//	}

}
