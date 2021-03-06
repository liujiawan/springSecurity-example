package com.sse.oauth2.server.service;

import com.sse.oauth2.model.SysPermission;
import com.sse.oauth2.model.SysUser;
import com.sse.oauth2.service.SysPermissionService;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;

/**
 * @version : 1.0.0
 * @author: GL
 * @create: 2020年 06月 10日 18:06
 **/
public abstract class AbstractUserDetailsService implements UserDetailsService {

    @Autowired
    private SysPermissionService sysPermissionService;

    /**
     * 每次登录都会调用这个方法验证用户信息
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        /**
         * 通过请求的用户名去数据库中查询用户信息，这里用户信息都查询出来了，密码也就获取到了。
         */
        SysUser sysUser = findSysUser(username);

        /**
         * 查询权限
         */
        findSysPermission(sysUser);
        return sysUser;
    }

    /**
     * @param usernameOrMobile 用户或手机号
     * @return
     * @throws UsernameNotFoundException
     */
    abstract SysUser findSysUser(String usernameOrMobile);

    /**
     * 查询认证信息
     * @param sysUser
     * @throws UsernameNotFoundException
     */
    public void findSysPermission(SysUser sysUser) throws UsernameNotFoundException{
        if(sysUser == null) {
            throw new UsernameNotFoundException("未查询到有效用户信息");
        }

        // 2. 查询该用户有哪一些权限
        List<SysPermission> sysPermissions =
                sysPermissionService.findByUserId(sysUser.getId());

        // 无权限
        if(CollectionUtils.isEmpty(sysPermissions)) {
            return;
        }

        // 存入权限,认证通过后用于渲染左侧菜单
        sysUser.setPermissions(sysPermissions);

        // 3. 封装用户信息和权限信息
        List<GrantedAuthority> authorities = new ArrayList<>();
        for(SysPermission sp: sysPermissions) {
            //权限标识
            authorities.add(new SimpleGrantedAuthority(sp.getCode()));
        }
        sysUser.setAuthorities(authorities);
    }
}
