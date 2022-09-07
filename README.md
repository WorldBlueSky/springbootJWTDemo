# JWT 认证教程



## 一、介绍以下认证的方式



**session**

最开始 我们登陆的时候，是将 对象存到session当中，每次请求的时候，取session中是否存在该对象进而判断是否通过认证。



**token+redis**

然后是 token+redis 的方式，将seesionID 作为 token，存储到redis中（token:user），并设置过期时间，同时将 token 通过响应传回给 浏览器，存储到 localstory，每次请求的时候把token放到请求的header中，查询redis一致的话，通过认证。



**JWT（JSON Web token）**

用于各方之间通过json对象安全传输信息，此信息可以验证信任，jwt使用 hamc算法，或使用rsa公钥进行签名



## 二、JWT 能做什么？



主要是授权验证，一旦用户登录，后续的每个请求都包括JWT，从而允许用户访问该令牌允许用过的路由，他的开销很小并且可以在不同的域中进行使用



## 三、与传统的seesion存储的区别？

1、每个用户经过数据库验证（用户名密码）之后，都会在服务端做一次记录，session保存在服务器内存中，随着认证用户的增多，服务器开销变得很大。而token服务器端只生成并返回给浏览器端，并不占内存空间。



2、如果 一个分布式系统，很多功能通过负载均衡放在不同的服务器上，那么如果只是session的话，因为sesiion只保存到访问服务器的内存中，分布式的其他服务器拿不到session，总之很麻烦。token 字符串只生成一次，每一台服务都知道token，进行过验证即可。



3、session是通过cookie进行用户识别的，session设置之后，将sessionID存储到 cookie中的 JsessionID 中，下一次还通过cookie中的JsessionID 到客户端找session,中间可能会cookie被截获，那么就很有可能遭到跨站请求伪造的攻击。



 4、前后端分离系统，在应用解耦增加了部署的复杂性，一次请求多次转发。如果后端是多节点部署，那还要实现 session共享机制，不方便集群应用。



## 四、JWT 如何认证？



前端通过一个 表单将 username、password 发送到后端的接口，这是一个Http Post 请求，建议使用 SSL加密的传输，避免泄露信息。

后端核实密码之后，将 用户（user）不敏感的信息(id,username,img)作为 JWT的payload，将其与header部分进行Base64 编码拼接 上后面的 signature，形成一个 JTW，最后的JWT像是一个 xxxx.yyy.zzz 的一个字符串。

token的三个部分： header、payload、signature

 后端将token通过响应返回给前端，可存储到localStroy 或者seesionStory 中，退出登陆时，前端删除保存的JWT即可。

前端每次在请求的时候，将JWT放到 header 的 Authorization中，后端检查请求头是否存在 token，以及验证时效性，检查签名的正确性等，正确即通过授权。



## 五、JWT的优势？

1、简洁：可以通过url、post参数、或者在header中发送，数据量很小，传输速度也很快

2、自包含，JTW的 payload部分包含着一些我们需要的用户信息，不同频繁查询数据库了，但是不能放密码等敏感信息，因为Base64 可以解码。

3、因为token是JSon加密的方式保存到客户端的，所有JWT是跨语言的，所有的web形式都支持。

4、不需要在服务器端进行设置session信息，适合用于分布式微服务



## 六、JWT的组成



token 是一个字符串 =》 xxx.yyy.zzz



### （1）token 组成

1、标头（header）

2、有效载荷 （payload）

3、签名（signature）



### （2）header 部分

表头一般包含两部分，一个是type令牌的类型，一个是签名使用的加密算法。标头会使用Base64 编码组成JWT的一部分。

```json
{
    "alg":"HS256", // 表示签名使用的加密算法
    "typ":"JWT" // 表示标头的类型
}
```



### （3）payload 部分

这一部分是有效载荷，通常是登陆用户的一些不敏感信息，使用Base64 加密组成 token的第二部分。

```json
// 这一部分的信息都是自己声明、自己定义的
{
    "username":"admin",
    "nickname":"world",
    "admin":true
}
```

### （4）signature 部分

前两部分是可以通过 Base64 解码得到的，但是signature 是使用编码后的header、payload 以及一个密钥，使用header声明的签名算法进行签名，签名的作用是 保证 JWT没有篡改过。



因为base64是可以解码的，如果token中的header、payload中的信息解码然后修改，在进行编码。最终加上之前的signature形成新的JWT的话，那么首先服务器端会判断除JWT的header、payload形成的签名与自己附带的签名不一致，如果黑客也对签名进行修改了的话，服务器端还会通过密钥对签名进行验证。黑客亦不会得到这个密钥的，因为不涉及到传输，在服务器内部。



### （5）信息安全问题

有人说JWT是Base64 编码的，是可逆的，那我们传输的信息不就泄露了吗？确实是这样的结果，所以我们在JWT中的peyload不要放置敏感的信息（密码），否则第三方解码很容易得知这些信息。



## 七、JWT的第一个程序



### 1、引入JWT依赖



去maven仓库搜索 jwt的依赖

```xml
<!-- https://mvnrepository.com/artifact/com.auth0/java-jwt -->
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.19.2</version>
</dependency>
```



### 2、生成Token令牌



需要我们了解



> 生成token的方法  `JWT.create()`

> 设计header的方法 `withHeader()`,内部是map类型

> 设计payload的方法  `withClaim("","")`， 放的也是一些自定义的键值对

> 设计签名的方法 `sign()` 需要设计签名算法、签名密钥

> 设计过期时间 `withExpiresAt()` ,内部是一个Date类型的，我们使用Calendar 设置一段时间



```java
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

```



### 3、验证并解析 Token 令牌



生成一个token验证对象 `require(加密方法(密钥)).build()`

执行验证token的方法，获取一个解码对象 `verify(token)`

获取payload得转化类型 `asString()` `asInt()`



```java
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

```



## 八、JWT的工具类整合



jwt主要就是两个方法，一个是生成token，一个是验证token解析内容

我们通过整合JWT工具类，封装三个方法，一个是生成令牌的，一个是验证令牌，一个是获取payload信息



## 九、SpringBoot 集成 JWT



### （0）Utils层



JWT工具类 JWTUtils



```java
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

```





###  （1）POJO层



pojo基础用户实体类



```java
package com.demo.pojo;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    public Integer id;
    public String username;
    public String password;
}

```



### （2）Mapper 层



UserMapper 持久层类



```java
package com.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.demo.pojo.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {

}

```



### （3）Service 层



UserService 接口



```java
package com.demo.service;
import com.demo.pojo.User;

public interface UserService {
    User login(User user);
}


```



UserServiceImpl



```java
package com.demo.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.demo.mapper.UserMapper;
import com.demo.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private UserMapper userMapper;

    @Override
    public User login(User user) {
        // 根据接收的用户名和密码查询数据库
        QueryWrapper<User> wrapper =new QueryWrapper<>();
        wrapper.eq("username",user.getUsername())
                .eq("password",user.getPassword());

        User userDB = userMapper.selectOne(wrapper);
        if(userDB==null){
            throw new RuntimeException("登陆失败!");
        }

        return userDB;

    }

}



```



### （4）Controller 层



```java
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


```



### （5）拦截器层



使用JWT对 header中的 token进行验证



```java
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


```



### （6）配置层



将之前的 拦截器规则注册到 WebMVC 配置下



```java
package com.demo.config;

import com.demo.interceptors.JWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JWTInterceptor())
                .addPathPatterns("/**/*") // 禁止所有的非登陆页面
                .excludePathPatterns("/user/login"); // 放行登陆页面
    }
}


```



### （7）接口测试



对登陆进行接口测试，查询数据库匹配成功生成token



![图片](https://user-images.githubusercontent.com/109014171/188931965-4cbb9424-c823-4396-b8dd-614309be512f.png)




在header中使用token访问权限的接口，返回接口信息



![图片](https://user-images.githubusercontent.com/109014171/188932003-e56b0492-40a3-4176-84ec-6b803d58ae88.png)




未携带token，访问用户功能页，被拦截器拦截返回信息



![图片](https://user-images.githubusercontent.com/109014171/188932033-5c9ad4ab-3453-48a8-af10-3cf9619026d3.png)


