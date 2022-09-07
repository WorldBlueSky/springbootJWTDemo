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
