package kz.kalybayevv.Application.controllers.userController;

import kz.kalybayevv.Application.helpers.TokenHelper;
import kz.kalybayevv.Application.services.userService.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {
    private UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }


    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody User user) {
//        if (userService.loginUser(user).equals(new ResponseEntity<Object>("Successfully logged in", HttpStatus.OK))) {
//            response.setHeader("Authorization", user.generateUserToken(user.getPassword()) + "/" +
//                    user.getUsername());
//        }
        return userService.loginUser(user);
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody User user) {
        if (userService.checkEmail(user.getUsername()).equals(new ResponseEntity<Object>("Valid email", HttpStatus.OK))) {
            return userService.registerUser(user);
        } else {
            return userService.checkEmail(user.getUsername());
        }
    }


    @PostMapping("/addRoleToUser")
    public ResponseEntity<Object> createUser(@RequestParam("username") String username,
                                             @RequestParam("newUsername") String newUsername,
                                             @RequestParam("newRole") String newRole) {
        List<String> admins = userService.getAdmins();
        if (admins.contains(username)) {
            return userService.addRoleToUser(newUsername, newRole);
        } else {
            return new ResponseEntity<Object>("You don`t have access to create new User", HttpStatus.NOT_IMPLEMENTED);
        }
    }


    @PostMapping("/updateFirstName")
    public ResponseEntity<Object> updateFirstName(@RequestParam("username") String username,
                                                  @RequestParam("password") String password,
                                                  @RequestParam("newFirstName") String newName) {
        return userService.updateFirstName(username, password, newName);
    }


    @PostMapping("/updatePassword")
    public ResponseEntity<Object> updatePassword(@RequestParam("username") String username,
                                                 @RequestParam("password") String password,
                                                 @RequestParam("newPassword") String newPassword) {
        return userService.updatePassword(username, password, newPassword);
    }

    @PostMapping("/updateLastName")
    public ResponseEntity<Object> updateLastName(@RequestParam("username") String username,
                                                 @RequestParam("password") String password,
                                                 @RequestParam("newLastName") String newLastName) {
        return userService.updateLastName(username, password, newLastName);
    }

    @PostMapping("/deleteUser")
    public ResponseEntity<Object> deleteUser(@RequestParam("username") String username,
                                             @RequestParam("password") String password) {
        return userService.deleteByUsernameAndPassword(username, password);
    }

    @GetMapping("/getByUsername")
    public ResponseEntity<Object> getByUsername(@RequestParam("username") String username) {
        return userService.getByUsername(username);
    }

    @GetMapping("/tokens")
    public ResponseEntity<Object> getTokens() {
        return userService.getTokens();
    }


    @PostMapping("/logout")
    public ResponseEntity<Object> logout(@RequestBody User user) {
        return userService.logout(user);
    }

    @GetMapping("/check")
    public ResponseEntity<Object> check(HttpServletRequest request) {
        String token = request.getHeader("token");
        String email = TokenHelper.getEmailByToken(token);
        if (userService.containsUser(email)) {
            return ResponseEntity.ok(email);
        } else {
            return new ResponseEntity<Object>("Invalid token", HttpStatus.NOT_FOUND);
        }
    }
}
