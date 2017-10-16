package com.github.zhangkaitao.shiro.chapter6.realm;

import com.github.zhangkaitao.shiro.chapter6.BaseTest;
import junit.framework.Assert;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.junit.Test;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-28
 * <p>Version: 1.0
 */
public class UserRealmTest extends BaseTest {
    
	/**
	 * 首先要看BaseTest这个文件，它初始化了数据库中的内容
	 * 由于用了正确的用户名和密码，所以认证成功.
	 */
    @Test
      public void testLoginSuccess() {    	
        login("classpath:shiro.ini", u1.getUsername(), password);
        Assert.assertTrue(subject().isAuthenticated());
    }
    /**
     * 使用了一个不存在的用户名，所以在UserRealm中找不到这个用户，抛出异常
     */
    @Test(expected = UnknownAccountException.class)
    public void testLoginFailWithUnknownUsername() {
        login("classpath:shiro.ini", u1.getUsername() + "1", password);
    }
    
    /**
     * 用了一个不正确的密码，抛出密码匹配异常
     */
    @Test(expected = IncorrectCredentialsException.class)
    public void testLoginFailWithErrorPassowrd() {
        login("classpath:shiro.ini", u1.getUsername(), password + "1");
    }
    /**
     * 用户 4,在创建时，设定了一个锁定位，所以抛出锁定异常
     */
    @Test(expected = LockedAccountException.class)
    public void testLoginFailWithLocked() {
        login("classpath:shiro.ini", u4.getUsername(), password + "1");
    }

    /**
     * 这里连续试了5次错误的密码。
     * 由于密码匹配算法中增加了限制连续5次输入错误，就抛出异重试异常。
     * 连续输入的错误次数保存在ehcache中，根据配置，需要1小时后才会失效。
     * 这样做的目的是为了防止暴力破解。
     */
    @Test(expected = ExcessiveAttemptsException.class)
    public void testLoginFailWithLimitRetryCount() {
        for(int i = 1; i <= 5; i++) {
            try {
                login("classpath:shiro.ini", u3.getUsername(), password + "1");
            } catch (Exception e) {/*ignore*/}
        }
        login("classpath:shiro.ini", u3.getUsername(), password + "1");

        //需要清空缓存，否则后续的执行就会遇到问题(或者使用一个全新账户测试)
    }


    @Test
    public void testHasRole() {
        login("classpath:shiro.ini", u1.getUsername(), password );
        Assert.assertTrue(subject().hasRole("admin"));
    }

    @Test
    public void testNoRole() {
        login("classpath:shiro.ini", u2.getUsername(), password);
        Assert.assertFalse(subject().hasRole("admin"));
    }

    @Test
    public void testHasPermission() {
        login("classpath:shiro.ini", u1.getUsername(), password);
        Assert.assertTrue(subject().isPermittedAll("user:create", "menu:create"));
    }

    @Test
    public void testNoPermission() {
        login("classpath:shiro.ini", u2.getUsername(), password);
        Assert.assertFalse(subject().isPermitted("user:create"));
    }

}
