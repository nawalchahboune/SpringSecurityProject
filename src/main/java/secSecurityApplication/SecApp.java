package secSecurityApplication;

import java.util.ArrayList;

import org.sid.AppRole;
import org.sid.AppUser;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import service.Service1;

//@EnableJpaRepositories(basePackages = "sec.org.repo")
@EnableJpaRepositories(basePackages = "sec.org.repo")
@EntityScan(basePackages = "org.sid")


@SpringBootApplication(scanBasePackages = {"sec.org.repo","org.sid", "service","secSecurityApplication"})

public class SecApp {




    public static void main(String[] args) {
        SpringApplication.run(SecApp.class, args);
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner commandLineRunner( Service1 accountService) {
        return args -> {
            AppRole role1 = new AppRole(null,"admin");
            AppRole role2 = new AppRole(null,"apiculteur");
            AppRole role3 = new AppRole(null,"agriculteur");
            AppUser user1= new AppUser(null,"nawal","username","1234",new ArrayList<AppRole>());
            AppUser user2= new AppUser(null,"hicham","username2","2345", new ArrayList<AppRole>());
            accountService.addNewRole(role1);
            accountService.addNewRole(role2);
            accountService.addNewRole(role3);
            accountService.addNewUser(user1);
            accountService.addNewUser(user2);
            accountService.addRoleToUser(user1,role1);
            accountService.addRoleToUser(user2,role1);
            accountService.addRoleToUser(user1,role2);
            accountService.addRoleToUser(user2,role3);
        };

    }
}
