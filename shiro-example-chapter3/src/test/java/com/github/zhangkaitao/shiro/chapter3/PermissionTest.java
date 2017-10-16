package com.github.zhangkaitao.shiro.chapter3;

import junit.framework.Assert;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.junit.Test;

import java.util.Arrays;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-26
 * <p>Version: 1.0
 */
public class PermissionTest extends BaseTest {
	/**
	 * 基于资源的访问控制（显示角色）
	 * 在ini配置文件中，配置角色，以及角色与权限之间的关系
	 * 规则：“用户名=密码，角色1，角色2”“角色=权限1，权限2”;
	 * 即首先根据用户名找到角色，然后根据角色再找到权限；即角色是权限集合；
	 * Shiro同样不进行权限的维护，需要我们通过Realm返回相应的权限信息。
	 * 只需要维护“用户——角色”之间的关系即可
	 * 
	 * 基于资源的访问控制（显示角色）就完成了，也可以叫基于权限的访问控制，
	 * 这种方式的一般规则是“资源标识符：操作”，即是资源级别的粒度；
	 * 这种方式的好处就是如果要修改基本都是一个资源级别的修改，不会对其他模块代码产生影响，粒度小。
	 * 但是实现起来可能稍微复杂点，需要维护“用户——角色，角色——权限（资源：操作）”之间的关系。  
	 */
    @Test
    public void testIsPermitted() {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //判断拥有权限：user:create
        //注意:这里直接判断用户是否捅有某权限，而不是先检测用户捅有某个角色，再检测用户捅有某个权限。       
        //也就是说，间接检测了[用户->角色]这一层关系
        Assert.assertTrue(subject().isPermitted("user:create"));
        //判断拥有权限：user:update and user:delete
        Assert.assertTrue(subject().isPermittedAll("user:update", "user:delete"));
        //判断没有权限：user:view
        Assert.assertFalse(subject().isPermitted("user:view"));
    }

    @Test(expected = UnauthorizedException.class)
    public void testCheckPermission() {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //断言拥有权限：user:create
        subject().checkPermission("user:create");
        //断言拥有权限：user:delete and user:update
        subject().checkPermissions("user:delete", "user:update");
        //断言拥有权限：user:view 失败抛出异常
        subject().checkPermissions("user:view");
    }


    @Test
    public void testWildcardPermission1() {
        login("classpath:shiro-permission.ini", "li", "123");

        subject().checkPermissions("system:user:update", "system:user:delete");
        subject().checkPermissions("system:user:update,delete");
    }

    @Test
    public void testWildcardPermission2() {
        login("classpath:shiro-permission.ini", "li", "123");
        subject().checkPermissions("system:user:create,delete,update:view");

        subject().checkPermissions("system:user:*");
        subject().checkPermissions("system:user");
    }

    @Test
    public void testWildcardPermission3() {
        login("classpath:shiro-permission.ini", "li", "123");
        subject().checkPermissions("user:view");

        subject().checkPermissions("system:user:view");
    }

    @Test
    public void testWildcardPermission4() {
        login("classpath:shiro-permission.ini", "li", "123");
        subject().checkPermissions("user:view:1");

        subject().checkPermissions("user:delete,update:1");
        subject().checkPermissions("user:update:1", "user:delete:1");

        subject().checkPermissions("user:update:1", "user:delete:1", "user:view:1");

        subject().checkPermissions("user:auth:1", "user:auth:2");

    }

    @Test
    public void testWildcardPermission5() {
        login("classpath:shiro-permission.ini", "li", "123");
        subject().checkPermissions("menu:view:1");

        subject().checkPermissions("organization");
        subject().checkPermissions("organization:view");
        subject().checkPermissions("organization:view:1");

    }


    @Test
    public void testWildcardPermission6() {
        login("classpath:shiro-permission.ini", "li", "123");
        subject().checkPermission("menu:view:1");
        subject().checkPermission(new WildcardPermission("menu:view:1"));

    }



}
