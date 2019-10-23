package ee.praktika.springsecurity.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping( "/showMyLoginPage" )
    public String showMyLoginPage(){

        //        return "plain-login"; //maps over to /WEB-INF/view/plain-login.jsp --> need to create the file
        return "fancy-login"; //maps to the fancy bootstrap login container view
    }

    //adding access-denied request mapping
    @GetMapping( "/access-denied" )
    public String showAccessDenied(){

        return "access-denied";
    }
}
