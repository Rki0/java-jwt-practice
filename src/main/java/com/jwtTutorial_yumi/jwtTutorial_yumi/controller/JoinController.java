package com.jwtTutorial_yumi.jwtTutorial_yumi.controller;

import com.jwtTutorial_yumi.jwtTutorial_yumi.dto.JoinDTO;
import com.jwtTutorial_yumi.jwtTutorial_yumi.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {
    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {
        joinService.joinProcess(joinDTO);

        return "ok";
    }
}
