package com.fanxl.demo.security.jwt.service;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/***
 * 1.加载所有需要鉴权的url列表，指定每个url对应的，需要的访问权限的collection集合。
 * 2.根据访问的url，获取到该url是否需要鉴权，如需要，把该url需要的权限列表collection传递给MyAccessDecisionManager.decide()方法进行权限
 *   验证。
 * @author fanxl
 * @date 2020/9/27 9:30
*/
@Service
public class MyInvocationSecurityMetadataSourceService implements
        FilterInvocationSecurityMetadataSource {

//    @Autowired
//    private PermissionMapper permissionMapper;

    private HashMap<String, Collection<ConfigAttribute>> map =null;

    /**
     * 加载权限表中所有权限
     */
    public void loadResourceDefine(){
        map = new HashMap<>();
        Collection<ConfigAttribute> array;
//        ConfigAttribute cfg;
        //List<Permission> permissions = permissionMapper.findAll();
//        for(Permission permission : permissions) {
//            array = new ArrayList<>();
//            cfg = new SecurityConfig("ROLE_"+permission.getName());
//            //此处只添加了用户的名字，其实还可以添加更多权限的信息，例如请求方法到ConfigAttribute的集合中去。此处添加的信息将会作为MyAccessDecisionManager类的decide的第三个参数。
//            array.add(cfg);
//            //用权限的getUrl() 作为map的key，用ConfigAttribute的集合作为 value，
//            map.put(permission.getUrl(), array);
//        }
        array = new ArrayList<>();
        ConfigAttribute cfg = new SecurityConfig("ROLE_ADMIN");
        ConfigAttribute cfg1 = new SecurityConfig("ROLE_USER");
        //此处只添加了用户的名字，其实还可以添加更多权限的信息，例如请求方法到ConfigAttribute的集合中去。此处添加的信息将会作为MyAccessDecisionManager类的decide的第三个参数。
        array.add(cfg);
        array.add(cfg1);
        //用权限的getUrl() 作为map的key，用ConfigAttribute的集合作为 value，
        map.put("/article/test", array);

    }

    //object 包含客户端发起的请求的requset信息，可转换为 HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
    //此方法是为了判定用户请求的url 是否在权限表中，如果在权限表中，则返回给 decide 方法，用来判定用户是否有此权限。如果不在权限表中则放行。
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        if(map ==null) loadResourceDefine();
        //object 中包含用户请求的request 信息
        HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
        AntPathRequestMatcher matcher;
        String resUrl;
        for(Iterator<String> iter = map.keySet().iterator(); iter.hasNext(); ) {
            resUrl = iter.next();
            matcher = new AntPathRequestMatcher(resUrl);
            if(matcher.matches(request)) {
                return map.get(resUrl);
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}