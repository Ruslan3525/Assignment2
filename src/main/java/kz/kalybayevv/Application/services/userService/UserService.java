package kz.kalybayevv.Application.services.userService;

import kz.kalybayevv.Application.controllers.userController.User;
import kz.kalybayevv.Application.helpers.TokenHelper;
import kz.kalybayevv.Application.helpers.ValidateHelper;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.token.Token;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UserService {
    private Map<Integer, User> map = new HashMap<>();
    private Map<Integer, String> tokens = new HashMap<>();
    private Map<String, String> loggedUsers = new HashMap<>();
    private List<String> admins = new ArrayList<>();
    private int ID = 0;


    public ResponseEntity<Object> registerUser(User user) {
        if (user.getPassword() != null && user.getUsername() != null) {
            for (Integer userId : map.keySet()) {
                if (map.get(userId).getUsername().equals(user.getUsername())) {
                    return new ResponseEntity<Object>("username already exist", HttpStatus.NOT_IMPLEMENTED);
                }
            }
            user.setRole("ROLE_USER");
            map.put(++ID, user);
            tokens.put(ID, TokenHelper.getToken(user.getUsername()));
            return new ResponseEntity<Object>("User successfully registered", HttpStatus.OK);
        }
        return new ResponseEntity<Object>("Bad Credentials", HttpStatus.NOT_IMPLEMENTED);
    }

    public ResponseEntity<Object> loginUser(User user) {
        if (user != null) {
//            String isUserLogged = loggedUsers.get(user.getUsername());
            if (loggedUsers.containsKey(user.getUsername())) {
                return new ResponseEntity<Object>("You already logged in", HttpStatus.NOT_IMPLEMENTED);
            } else {
                for (Integer userId : map.keySet()) {
                    if (map.get(userId).getUsername().equals(user.getUsername()) &&
                            map.get(userId).getPassword().equals(user.getPassword())) {
                        loggedUsers.put(user.getUsername(), "logged");
                        if (map.get(userId).getRole().equals("ROLE_SUPER_ADMIN")) {
                            admins.add(user.getUsername());
                        }
                        return new ResponseEntity<Object>("Successfully logged in", HttpStatus.OK);
                    }
                }
            }
        }
        return new ResponseEntity<Object>("Bad Credentials", HttpStatus.NOT_IMPLEMENTED);
    }


    public ResponseEntity<Object> getTokens() {
        return new ResponseEntity<Object>(tokens, HttpStatus.OK);
    }

    public ResponseEntity<Object> logout(User user) {
//        String info = loggedUsers.get(user.getUsername());
        if (!loggedUsers.containsKey(user.getUsername())) {
            return new ResponseEntity<Object>("You are not logged in", HttpStatus.NOT_FOUND);
        } else {
            loggedUsers.remove(user.getUsername());
            return new ResponseEntity<Object>("Logged out successfully", HttpStatus.OK);
        }
    }


    public ResponseEntity<Object> updateFirstName(String username, String password, String newName) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(username) && map.get(userId).getPassword().equals(password)) {
                map.get(userId).setFirst_name(newName);
                return new ResponseEntity<Object>("First name changed successfully", HttpStatus.OK);
            }
        }
        return new ResponseEntity<Object>("Bad Credentials", HttpStatus.NOT_IMPLEMENTED);
    }

    public ResponseEntity<Object> updatePassword(String username, String password, String newPassword) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(username) && map.get(userId).getPassword().equals(password)) {
                map.get(userId).setPassword(newPassword);
                return new ResponseEntity<Object>("Password changed successfully", HttpStatus.OK);
            }
        }
        return new ResponseEntity<Object>("Bad Credentials", HttpStatus.NOT_IMPLEMENTED);
    }

    public ResponseEntity<Object> updateLastName(String username, String password, String newLastName) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(username) && map.get(userId).getPassword().equals(password)) {
                map.get(userId).setLast_name(newLastName);
                return new ResponseEntity<Object>("Last Name changed successfully", HttpStatus.OK);
            }
        }
        return new ResponseEntity<Object>("User not found", HttpStatus.NOT_FOUND);
    }


    public ResponseEntity<Object> deleteByUsernameAndPassword(String username, String password) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(username) && map.get(userId).getPassword().equals(password)) {
                User user = new User(userId, username, password, map.get(userId).getRole()
                        , map.get(userId).getFirst_name(), map.get(userId).getLast_name());
                map.remove(userId, user);
                return new ResponseEntity<Object>("User deleted successfully", HttpStatus.OK);
            }
        }
        return new ResponseEntity<Object>("Bad credentials", HttpStatus.NOT_IMPLEMENTED);
    }

    public ResponseEntity<Object> getByUsername(String username) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(username)) {
                User user = new User(userId, map.get(userId).getUsername(),
                        map.get(userId).getPassword(), map.get(userId).getRole()
                        , map.get(userId).getFirst_name(), map.get(userId).getLast_name());
                return new ResponseEntity<Object>(user, HttpStatus.OK);
            }
        }
        return new ResponseEntity<Object>("User not found", HttpStatus.NOT_FOUND);
    }


    public ResponseEntity<Object> addRoleToUser(String newUsername, String newRole) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(newUsername)) {
                map.get(userId).setRole(newRole);
                return new ResponseEntity<Object>("role added successfully", HttpStatus.NOT_IMPLEMENTED);
            }
        }
        return new ResponseEntity<Object>("User not registered or username is not valid", HttpStatus.NOT_IMPLEMENTED);
    }


    public boolean containsUser(String username) {
        for (Integer userId : map.keySet()) {
            if (map.get(userId).getUsername().equals(username)) {
                return true;
            }
        }
        return false;
    }

    public ResponseEntity<Object> checkEmail(String email) {
        if (ValidateHelper.validate(email)) {
            return new ResponseEntity<Object>("Valid email", HttpStatus.OK);
        } else {
            return new ResponseEntity<Object>("Invalid email", HttpStatus.NOT_IMPLEMENTED);
        }
    }

    public List<String> getAdmins() {
        return admins;
    }
}
