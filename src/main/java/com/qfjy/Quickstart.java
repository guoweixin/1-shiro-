package com.qfjy;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *简单的快速入门应用程序，展示了如何使用Shiro的API
 */
public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


    public static void main(String[] args) {

/*
    使用配置的//域，用户，
    角色和权限创建Shiro SecurityManager的最简单方法是使用简单的INI配置。
    //我们将通过使用可以提取.ini文件并返回SecurityManager实例的工厂来实现：

    在类路径的根目录使用shiro.ini文件//（file：和url：前缀分别从文件和URL加载
 */
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();

       /*
       对于这个简单的示例快速入门，
       使SecurityManager可以作为JVM单例访问。
       大多数应用程序都不会这样做//而是依赖于他们的容器配置或web.xml来获取// webapps。
       这超出了这个简单的快速入门的范围，所以//我们只做最低限度的事情，这样你就可以继续感受//对于事物。

        */
        SecurityUtils.setSecurityManager(securityManager);

        // Now that a simple Shiro environment is set up, let's see what you can do:
        //现在设置了一个简单的Shiro环境，让我们看看你能做些什么：

        // get the currently executing user:   得到当前正在执行的用户
        Subject currentUser = SecurityUtils.getSubject();

        // Do some stuff with a Session (no need for a web or EJB container!!!)
        //用Session做一些事情（不需要web或EJB容器!!!）  Shiro展示如何存取Session
        Session session = currentUser.getSession();
        session.setAttribute("someKey", "aValue");
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("Retrieved the correct value! [" + value + "]");
        }

        // let's login the current user so we can check against roles and permissions:
        //让我们登录当前用户，以便我们检查角色和权限
        if (!currentUser.isAuthenticated()) { //当前Subject是否进行认证（登录）
            //前台用户传入的用户名和密码 (将用户名和密码封装到UsernamePasswordToken对象中）
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr123", "vespa123");
            token.setRememberMe(true);//记住我
            try {
                //进行认证（登录）功能
                currentUser.login(token);
            } catch (UnknownAccountException uae) {//未知帐户异常
                log.info("用户名不存在 " + token.getPrincipal());
                return ;
            } catch (IncorrectCredentialsException ice) { //凭证匹配器异常 不正确的凭据异常
                log.info("密码输入错误 " + token.getPrincipal() + " was incorrect!");
                return ;
            } catch (LockedAccountException lae) { //帐户锁定异常 锁定帐户例外  (将来要在业务逻辑中进行判断）
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
                return ;
            }
            // ... catch more exceptions here (maybe custom ones specific to your application?
            catch (AuthenticationException ae) { // 认证异常 身份验证异常
                log.info("用户名或密码不正确 " + token.getPrincipal() + " was incorrect!");
                return ;
            }
        }

        //say who they are:
        //print their identifying principal (in this case, a username):
        log.info("User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //test a role:  测试是否拥有某个角色
        if (currentUser.hasRole("schwartz")) {
            log.info("May the Schwartz be with you!");
        } else {
            log.info("Hello, mere mortal.");
        }

        //test a typed permission (not instance-level)  判断用户是否拥有某个权限
        if (currentUser.isPermitted("lightsaber:weild")) {
            log.info("You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //a (very powerful) Instance Level permission:
        if (currentUser.isPermitted("winnebago:drive:eagle5")) {
            log.info("You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //all done - log out!   登出
        currentUser.logout();

        System.exit(0);
    }
}
