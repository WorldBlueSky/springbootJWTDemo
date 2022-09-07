package com.demo.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

public class JWTUitls {

    private static final String SECRET = "!@#$%^&";//在真实开发中密钥更严谨，一定不要泄露

    /**
     * 生成token，得有header、payload、signature
     * 默认7天过期
     * 使用 HMAC256加密
     * 通过map传递 payload 中的有效载荷
     */
     public static String getToken(Map<String,String> map){
         Calendar calendar = Calendar.getInstance();
         calendar.add(Calendar.DATE,7);// 设置一个7天的时间段

         String secret = "!@#$%^&";// 这是服务器端计算签名的密钥

         JWTCreator.Builder builder = JWT.create();

         for (Map.Entry<String,String> entry:map.entrySet()) {// 设置自定义的键值对
             builder.withClaim(entry.getKey(),entry.getValue());
         }

         String token = builder.withExpiresAt(calendar.getTime())// 设置过期时间
                               .sign(Algorithm.HMAC256(SECRET));//  签名的设置,使用一种加密算法设置盐值 计算签名

         return token;
     }

    /**
     * 验证token合法性
     */
    public static DecodedJWT verify(String token){
        // 验证 token

        // 如果有问题的话，那么抛出各种异常
        return JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
        // 使用JWT的require，生成一个验证对象

    }

    /**
     * 解析token中的内容,先验证token合法性饭后返回token解码的对象
     */
    public static DecodedJWT getTokenInfo(String token){
        DecodedJWT verify =JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
        // 使用JWT的require，生成一个验证对象
        return verify;
    }

}
