package service;

import java.util.Collection;
import java.util.List;

import jakarta.transaction.Transactional;
import lombok.NoArgsConstructor;
import org.sid.AppRole;
import org.sid.AppUser;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import sec.org.repo.AppRoleRepository;
import sec.org.repo.AppUserRepository;

@Service
@Transactional
@NoArgsConstructor

public class Service1 implements IAccountService{
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AppRoleRepository appRoleRepository;

    @Autowired
    private AppUserRepository appUserRepository;

    public Service1(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository) {


        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
    }

    @Override
    public AppUser addNewUser(AppUser user) {
        String password = user.getPassword();
        user.setPassword(passwordEncoder.encode(password));
        return appUserRepository.save(user);
    }

    @Override
    public AppRole addNewRole(AppRole role) {
        return appRoleRepository.save(role);
    }

    @Override
    public void addRoleToUser(AppUser user, AppRole role) {
        Collection<AppRole> roles= user.getRoles();
        roles.add(role);
       user.setRoles(roles);
        appUserRepository.save(user);

    }


    @Override
    public void removeRoleFromUser(AppUser user, AppRole role) {
            user.getRoles().remove(role);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }


    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
