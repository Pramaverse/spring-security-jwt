package com.example.springsecurityjwt;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SpringSecurityJwtApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void unauthorizedUsersCanRegister() throws Exception {
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
	void userCanLoginAndReceiveJWTToken() throws Exception {
		this.mockMvc.perform(post("/auth/login")
						.content("{\"username\":\"admin\",\"password\":\"password\"}")
						.contentType("application/json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.jwt").isNotEmpty());
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

	@Test
	void userWithAdminRoleCanLoginAndAccessAdminURLs() throws Exception {
		MvcResult result = this.mockMvc.perform(post("/auth/login")
				.content("{\"username\":\"admin\",\"password\":\"password\"}")
				.contentType("application/json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.jwt").isNotEmpty())
				.andReturn();

		String jwtToken = JsonPath.read(result.getResponse().getContentAsString(), "$.jwt");

		this.mockMvc.perform(get("/admin/")
				.header("Authorization","Bearer " + jwtToken))
				.andExpect(status().isOk())
				.andExpect(content().string("Hello Admin"));
	}

	@Test
	void userWithAdminRoleCanLoginAndAccessUserURLs() throws Exception {
		MvcResult result = this.mockMvc.perform(post("/auth/login")
						.content("{\"username\":\"admin\",\"password\":\"password\"}")
						.contentType("application/json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.jwt").isNotEmpty())
				.andReturn();

		String jwtToken = JsonPath.read(result.getResponse().getContentAsString(), "$.jwt");

		this.mockMvc.perform(get("/user/")
						.header("Authorization","Bearer " + jwtToken))
				.andExpect(status().isOk())
				.andExpect(content().string("Hello User"));
	}

	@Test
	void userWithUserRoleCanLoginAndAccessUserURLs() throws Exception {
		String username = "something";
		String password = "pass";

		this.mockMvc.perform(post("/auth/register")
						.content("{\"username\":\""+ username +"\",\"password\":\"" + password + "\"}")
						.contentType("application/json"))
				.andExpect(status().isOk());

		MvcResult result = this.mockMvc.perform(post("/auth/login")
						.content("{\"username\":\""+ username +"\",\"password\":\"" + password + "\"}")
						.contentType("application/json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.jwt").isNotEmpty())
				.andReturn();

		String jwtToken = JsonPath.read(result.getResponse().getContentAsString(), "$.jwt");

		this.mockMvc.perform(get("/user/")
						.header("Authorization","Bearer " + jwtToken))
				.andExpect(status().isOk())
				.andExpect(content().string("Hello User"));
	}

	@Test
	void userWithUserRoleCanLoginAndNotAccessAdminURLs() throws Exception {
		String username = "Joy";
		String password = "pass";

		this.mockMvc.perform(post("/auth/register")
						.content("{\"username\":\""+ username +"\",\"password\":\"" + password + "\"}")
						.contentType("application/json"))
				.andExpect(status().isOk());

		MvcResult result = this.mockMvc.perform(post("/auth/login")
						.content("{\"username\":\""+ username +"\",\"password\":\"" + password + "\"}")
						.contentType("application/json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.jwt").isNotEmpty())
				.andReturn();

		String jwtToken = JsonPath.read(result.getResponse().getContentAsString(), "$.jwt");

		this.mockMvc.perform(get("/admin/")
						.header("Authorization","Bearer " + jwtToken))
				.andExpect(status().isForbidden());
	}

	@Test
	void userCannotLoginWithIncorrectCredentials() throws Exception {
		this.mockMvc.perform(post("/auth/login")
						.content("{\"username\":\"Incorrect\",\"password\":\"password\"}")
						.contentType("application/json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.user").isEmpty());
	}
}
