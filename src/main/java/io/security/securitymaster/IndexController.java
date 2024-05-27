package io.security.securitymaster;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class IndexController {

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }
    
    
}
