package org.launchcode.javawebdevtechjobsauthentication;

import org.launchcode.javawebdevtechjobsauthentication.controllers.AuthenticationController;
import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class AuthenticationFilter extends HandlerInterceptorAdapter {
    private static final List<String> allowedlist = Arrays.asList("/login", "/register", "/logout", "/css");
    private static boolean isAllowedlisted(String path) {
        for (String pathRoot : allowedlist) {
            if (path.startsWith(pathRoot)) {
                return true;
            }
        }
        return false;
    }
    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticationController authenticationController;
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {
        //don't require sign in for AllowedList Pages
        if(isAllowedlisted(request.getRequestURI())) {
            //returning true indicates that the request may proceed
            return true;
        }

        HttpSession session = request.getSession();
        User user = authenticationController.getUserFromSession(session);

        // The user is logged in
        if (user != null) {
            return true;
        }

        // The user is NOT logged in
        response.sendRedirect("/login");
        return false;
    }
}