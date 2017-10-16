package com.github.zhangkaitao.shiro.chapter3.permission;

import com.alibaba.druid.util.StringUtils;
import junit.framework.Assert;
import org.apache.shiro.authz.Permission;

/**
 *  规则
 *    +资源字符串+权限位+实例ID
 *
 *  以+开头 中间通过+分割
 *
 *  权限：
 *     0 表示所有权限
 *     1 新增 0001
 *     2 修改 0010
 *     4 删除 0100
 *     8 查看 1000
 *
 *  如 +user+10 表示对资源user拥有修改/查看权限
 *
 *  不考虑一些异常情况
 *
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-26
 * <p>Version: 1.0
 */
public class BitPermission implements Permission {

    private String resourceIdentify;
    private int permissionBit;
    private String instanceId;
    
    /**
     * 这里假设格式一定是可以正常解释的格式，即捅有：+分隔的每一个部分
     * @param permissionString
     */
    public BitPermission(String permissionString) {
        String[] array = permissionString.split("\\+");

        if(array.length > 1) {
            resourceIdentify = array[1];
        }

        if(StringUtils.isEmpty(resourceIdentify)) {
            resourceIdentify = "*";
        }

        if(array.length > 2) {
            permissionBit = Integer.valueOf(array[2]);
        }

        if(array.length > 3) {
            instanceId = array[3];
        }

        if(StringUtils.isEmpty(instanceId)) {
            instanceId = "*";
        }

    }
    /**
     * 举例: +*+0+abc
     * *：表示所有资源，0:表示所有权限,abc:表示资源的实例 
     *   即对所有资源的实例abc，捅有新增修改查看删除权限，通如下逻辑判断会返回true
     */
    @Override
    public boolean implies(Permission p) {
        if(!(p instanceof BitPermission)) {
            return false;
        }
        BitPermission other = (BitPermission) p;

        if(!("*".equals(this.resourceIdentify) || this.resourceIdentify.equals(other.resourceIdentify))) {
            return false;
        }

        if(!(this.permissionBit ==0 || (this.permissionBit & other.permissionBit) != 0)) {
            return false;
        }

        if(!("*".equals(this.instanceId) || this.instanceId.equals(other.instanceId))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "BitPermission{" +
                "resourceIdentify='" + resourceIdentify + '\'' +
                ", permissionBit=" + permissionBit +
                ", instanceId='" + instanceId + '\'' +
                '}';
    }
}
