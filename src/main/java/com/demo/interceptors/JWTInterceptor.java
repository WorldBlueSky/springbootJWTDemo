package com.demo.interceptors;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.demo.util.JWTUitls;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

public class JWTInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 推荐前端发送请求将 token 放在 header
        String token = request.getHeader("token");

        HashMap<String,Object> map = new HashMap<>();


        try {
            // 予以放行
            DecodedJWT verify  = JWTUitls.verify(token);// 验证令牌
            map.put("state",true);
            map.put("msg","验证token成功!");
            return true;

        } catch (SignatureVerificationException e) {// 签名匹配异常
            map.put("msg","无效签名!");
            e.printStackTrace();
        } catch (TokenExpiredException e){
            e.printStackTrace();
            map.put("msg","token已经过期!");
        } catch (AlgorithmMismatchException e){
            e.printStackTrace();
            map.put("msg","算法异常!");
        }catch (Exception e){
            e.printStackTrace();
            map.put("msg","无效签名!");
        }

        map.put("state",false);// 设置状态

        ObjectMapper objectMapper = new ObjectMapper();

        String json = objectMapper.writeValueAsString(map);
        response.setContentType("application/json;charset=utf8;");
        response.getWriter().write(json);

        return false;
    }

}
