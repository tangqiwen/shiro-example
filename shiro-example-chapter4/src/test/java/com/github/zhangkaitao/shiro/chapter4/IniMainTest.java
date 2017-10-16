package com.github.zhangkaitao.shiro.chapter4;

import com.alibaba.druid.pool.DruidDataSource;
import junit.framework.Assert;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.*;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import java.util.Arrays;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-27
 * <p>Version: 1.0
 */
public class IniMainTest {

	/**
	 * 演示了配置文件是ini 是如何注入参数的
	 * 1：创建对象 
	 * 		securityManager=org.apache.shiro.mgt.DefaultSecurityManager  
	 * 2：常量值setter注入 
	 * 		dataSource.driverClassName=com.mysql.jdbc.Driver  
	 * 		jdbcRealm.permissionsLookupEnabled=true   
	 * 3：对象引用setter注入 
	 * 		authenticator=org.apache.shiro.authc.pam.ModularRealmAuthenticator  
	 *		authenticationStrategy=org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy  
	 *		authenticator.authenticationStrategy=$authenticationStrategy  
	 *		securityManager.authenticator=$authenticator 
	 * 4:嵌套属性setter注入 
	 *      securityManager.authenticator.authenticationStrategy=$authenticationStrategy
	 * 5:byte数组setter注入      默认是使用Base64编码，也可以是0x开头的十六进制
	 * 		#base64 byte[]  
	 *		authenticator.bytes=aGVsbG8=  
	 *		#hex byte[]  
	 *		authenticator.bytes=0x68656c6c6f  
	 * 6：Array/Set/List setter注入  用豆号分隔，如下
	 *   authenticator.array=1,2,3  
	 * 	 authenticator.set=$jdbcRealm,$jdbcRealm
	 * 7：Map setter注入
	 *   格式是：map=key：value，key：value，可以注入常量及引用值，常量的话都看作字符串（即使有泛型也不会自动造型）。
	 *   authenticator.map=$jdbcRealm:$jdbcRealm,1:1,key:abc 
	 * 8：实例化/注入顺序   后边的覆盖前边的注入
	 */
    @Test
    public void test() {

        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory("classpath:shiro-config-main.ini");

        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();

        //将SecurityManager设置到SecurityUtils 方便全局使用
        SecurityUtils.setSecurityManager(securityManager);

        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        subject.login(token);

        Assert.assertTrue(subject.isAuthenticated());



    }
}
