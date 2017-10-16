package com.github.zhangkaitao.shiro.chapter2;

import junit.framework.Assert;

import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SessionsSecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Test;


/**
 * 认证测试程序，
 * 1：测试了多个Realm,使用不同的认证策略方式去认证
 * 2：通过这个程序，我们学会了如何添加多个Realm认证
 *   以及对多个Realm时，我们采用那种认证策略
 *   比如我们的需求是有：手机用户登陆，第三方登陆，，帐号登陆时
 *   那么我们只要任一其中一种方式登陆成功就可以了。这时我们就可以
 *   采用如下方法来实现，给securityManager.realms指定三个Realm
 *   分别是:ThirdRealm,MobileRealm,AccountRealm
 *   然后任选如下一个策略给securityManager.authenticator.authenticationStrategy即可:
 *     1：只要有一个Realm验证成功即可，和FirstSuccessfulStrategy不同，返回所有Realm身份验证成功的认证信息
 *    	org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy 
 *     2：只要有一个Realm验证成功即可，只返回第一个Realm身份验证成功的认证信息，其他的忽略；
 *     org.apache.shiro.authc.pam.FirstSuccessfulStrategy
 * 总结：
 *    到这里我们就把自定义认证Realm及认证策略搞定了。
 *    接下来要搞定授权。
 *    然后把Realm的认证信息和授权信息从数据库中获取。
 *    再接下来，用授权信息去限制资源的访问，
 *    用认证拦截url访问。
 *    然后就是session管理，缓存加速
 *    然后是实现后台方法的分配权限和角色
 * @author tony
 * 2017年9月22日
 */
public class AuthenticatorTest {

    @Test
    public void testAllSuccessfulStrategyWithSuccess() {    	
    	//这个配置文件，包括两个realm分别是MyRealm1,MyRealm3。
    	//它们的认证信息是一样的,即都是zhangsan ,123.
    	//指定的认证策略是，需要全部认证成功能，才算是成功。
    	//如果其中某一个认证不成功，那么就会抛出IncorrectCredentialsException异常
    	//比如我们将其中的MyRealm3的密码修改成1234。虽然在MyRealm1是通过了，但是MyRealm3发现密码不匹配.
    	//这时subject.login()抛出异常。那么就是用户没有登陆成功。
    	//我们可以在@Test后面加上下句代码，可以验证成功。
    	//(expected =org.apache.shiro.authc.IncorrectCredentialsException.class)
        login("classpath:shiro-authenticator-all-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(2, principalCollection.asList().size());
    }

    @Test(expected = UnknownAccountException.class)
    public void testAllSuccessfulStrategyWithFail() {
    	//由于MyRealm2的用户是wang.并且认证策略也是需要全部认证成功后，才表示认证成功
    	//由于MyRealm2认证时用户信息不匹配。所以抛出异常，login不成功。
        login("classpath:shiro-authenticator-all-fail.ini");
    }

    /**
     * 只要有一个Realm验证成功即可，和FirstSuccessfulStrategy不同，
     * 《返回所有Realm身份验证成功的认证信息》
     */
    @Test
    public void testAtLeastOneSuccessfulStrategyWithSuccess() {
    	//这里面使用的认证策略是只要有一个Realm认证成功，就表示认证成功了。即login成功。
    	//在下面的配置文件中，我们使用了三个Realm.分别是MyRealm1,MyReaml2, MyRealm3
    	//但是MyRealm2是身份不通的，而MyRealm1,MyRealm3是成功的。由于只要一个成功就可以了。
    	//所以login不会抛出认证异常，仍认为是login成功。并且我们可以得到两个身份信息
    	
    	//这种认证策略非常的有用。比如第三方登陆，手机登陆，帐号登陆这些认证策略就可以用的上    
        login("classpath:shiro-authenticator-atLeastOne-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(2, principalCollection.asList().size());
        
        System.out.println(principalCollection.asList().get(0).toString());              
        
//        subject.getPrincipals();        
//        System.out.println(authentications.get(0).getPrincipals());
//        System.out.println(authentications.get(1).getPrincipals());
        
    }
    
    /**
     * 
     * 这里的FirstOneSuccess的意思是，返回第一个认证成功的AuthenticationInfo
     * 而不是说第一个MyRealm1要认证成功。强调的是:
     * 只要有一个Realm验证成功即可，只返回第一个Realm身份验证成功的认证信息，其他的忽略；
     */
    @Test
    public void testFirstOneSuccessfulStrategyWithSuccess() {
        login("classpath:shiro-authenticator-first-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，其包含了第一个Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(1, principalCollection.asList().size());
    }

    /**
     * 在这个验证策略中，必须要2个验证成功才能login成功。
     * 由于ini文件中的MyRealm1,MyRealm4中返回的身份信息是一样的。所以合并身份信息时
     * 发现完全一样，因此就只返回一个身份信息。
     * 如果我们把MyRealm4改成MyRealm3,并且由于这两个都成功了,那么就会返回两个身份信息。
     * 如果我们去掉MyRealm4,那么由于只有MyRealm1能通过。而我们需要2个，所以会失败
     * 
     */
    @Test
    public void testAtLeastTwoStrategyWithSuccess() {
        login("classpath:shiro-authenticator-atLeastTwo-success.ini");
        Subject subject = SecurityUtils.getSubject();

        //得到一个身份集合，因为myRealm1和myRealm4返回的身份一样所以输出时只返回一个
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(1, principalCollection.asList().size());
    }

    
    /**
     * 当认证通过的身份信息超过1个时，抛出异常
     * 也即当有多个Realm时，这些Realm中，只能有一个通过认证。就成功。否则抛出异常
     */
    @Test
    public void testOnlyOneStrategyWithSuccess() {
        login("classpath:shiro-authenticator-onlyone-success.ini");
        Subject subject = SecurityUtils.getSubject();

       
        PrincipalCollection principalCollection = subject.getPrincipals();
        Assert.assertEquals(1, principalCollection.asList().size());
    }

    /**
     * 
     * 公用的登陆方法
     * 
     * @param configFile
     */
    private void login(String configFile) {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory(configFile);

        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        subject.login(token);
    }

    @After
    public void tearDown() throws Exception {
        ThreadContext.unbindSubject();//退出时请解除绑定Subject到线程 否则对下次测试造成影响
    }

}
