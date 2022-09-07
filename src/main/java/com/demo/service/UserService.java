package com.demo.service;

import com.demo.pojo.User;
import org.springframework.stereotype.Service;

public interface UserService {

    User login(User user);
}
