package com.demo.pojo;

import com.sun.org.apache.xerces.internal.impl.xpath.XPath;
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
