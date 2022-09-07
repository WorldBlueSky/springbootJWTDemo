package com.demo.controller;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.pojo.User;
import com.demo.service.UserService;
import com.demo.util.JWTUitls;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

@RestController
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/user/login")
    public Map<String,Object> login(@RequestParam("name") String username,@RequestParam("pwd") String password){
      Map<String,Object> result = new HashMap<>();

      User user = new User(0,username,password);

        try {
            User userDB = userService.login(user); // 在数据库中查询是否用户名存在

            HashMap<String,String> payload = new HashMap<>();
            payload.put("id",userDB.getId().toString());
            payload.put("username",userDB.getUsername());

            // 生成JWT令牌
            String token  = JWTUitls.getToken(payload);

            result.put("state",true);
            result.put("msg","登陆成功!");
            result.put("token",token);


        } catch (Exception e) {
            e.printStackTrace();
            result.put("state",false);
            result.put("msg","登陆异常!");
        }

        return result;
    }

    /**
     * 一个token用户授权的功能接口
     * @param request
     * @return
     */
    @RequestMapping("/user/test")
    public Map<String,Object> test(HttpServletRequest request){

        HashMap<String,Object> map = new HashMap<>();

        // 处理自己的逻辑业务
        // 此时我们想要获取 token中的用户信息，token经过拦截器拦截绝对是正确的
       String token = request.getHeader("token");

        DecodedJWT tokenInfo = JWTUitls.getTokenInfo(token);

        User user = new User(Integer.parseInt(tokenInfo.getClaim("id").asString()),tokenInfo.getClaim("username").asString(),null);

        // 返回用户的相关信息的map集合
        map.put("data",user);
        map.put("state",true);
        map.put("msg","请求成功!");

        return map;
    }

}
