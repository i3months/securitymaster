package io.security.securitymaster;

import java.util.List;

import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

@Service
public class DataService {

    @PreFilter("filterObject.owner == authentication.name")
    public List<Account> write(List<Account> data) {
        return data;
    }
    
}
