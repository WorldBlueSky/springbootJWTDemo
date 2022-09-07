package com.demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@SpringBootTest
class DemoApplicationTests {

    /**
     * 获取令牌的方式
     */
    @Test
    void contextLoads() {
        Map<String,Object> map = new HashMap<>();
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE,30);// 设置一个2分钟的时间段

        String secret = "!@#$%^&";// 这是服务器端计算签名的密钥

         String token= JWT.create()
                .withHeader(map) // header中放的是一个map集合，默认就行 typ、alg
                .withClaim("uid",1) // payload 放一些自定义类型的键值对
                .withClaim("userName","admin")
                .withClaim("nickName","dog")
                .withExpiresAt(calendar.getTime()) // 设置过期时间
                .sign(Algorithm.HMAC256(secret)); // 签名的设置,使用一种加密算法设置盐值 计算签名

        System.out.println(token);
    }

    /**
     *验证并解析Token
     */
    @Test
    void test2(){
        // 验证 token

        String srcret = "!@#$%^&"; // 这个密钥需要与我们生成token的时候保持一致
        // 同时我们加密的算法也得和之前 生成token的时候保持一致

        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(srcret)).build();// 使用JWT的require，生成一个验证对象

        String token ="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm5pY2tOYW1lIjoiZG9nIiwidXNlck5hbWUiOiJhZG1pbiIsImV4cCI6MTY2MjU2MzQxNX0.XveUO2ZQ2wvs0K24GOTa3cn0F1q1IKKyq5WPSSJwXm8";

        DecodedJWT verify = jwtVerifier.verify(token); // 根据token生成一个解码对象

        // 解码这个过程中。会遇到各种异常，会在我们的控制台输出
        //1、token 字符串类型错误，不符合JSON的格式  The string 'xxx.yyy.zzz' doesn't have a valid JSON format.
        //2、 token 令牌过期异常
        //3、payload\header 被修改过了，签名不一致异常
        // 4、前后算法不一致、前后密钥不一致等等， 算法不匹配异常

        // 如果解析成功的话，那么我们是可以对解码对象进行获取之前设置的内容的
        System.out.println(verify.getClaim("uid").asLong()); // 虽然说解码了，但是如果直接去header、payload得到的就是base64解码的字符串，还是看不懂
        System.out.println(verify.getClaim("userName").asString()); // 需要我们再次进行as转换类型，才能得到内容
        System.out.println(verify.getClaim("nickName").asString());

    }

}
