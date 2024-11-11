package service;

import java.util.List;

import org.sid.AppRole;
import org.sid.AppUser;

public interface IAccountService {
    AppUser addNewUser(AppUser user);
    AppRole addNewRole(AppRole role);
    void addRoleToUser(AppUser user, AppRole role);
    void removeRoleFromUser(AppUser user, AppRole role);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();

}
