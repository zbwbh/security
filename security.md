

## 从一个Spring Security的例子开始
### 创建不受保护的应用

创建一个springboot的web应用

    @Controller
    public class AppController {
    
        @RequestMapping("/hello")
        @ResponseBody
        String home() {
            return "Hello ,spring security!";
        }
    }    
我们启动应用，假设端口是8080，那么当我们在浏览器访问http://localhost:8080/hello的时候可以在浏览器看到Hello ,spring security!。


### 加入spring security 保护应用

此时，/hello是可以自由访问。假设，我们需要具有某个角色的用户才能访问的时候，我们可以引入spring security来进行保护。加入如下依赖，并重启应用：

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

### 使用form表单页面登录

spring security 默认提供了表单登录的功能。我们新建一个类SecurityConfiguration,并加入一些代码，如下所示：

    @Configuration
    @EnableWebSecurity
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().and()
                    .httpBasic();
        }
    }
上面的代码其实就是 一种配置，authorizeRequests() 定义哪些URL需要被保护、哪些不需要被保护。 formLogin() 定义当需要用户登录时候，转到的登录页面。此时，我们并没有写登录页面，但是spring security默认提供了一个登录页面，以及登录控制器。

加完了上面的配置类之后，我们重启应用。然后继续访问http://localhost:8080/hello。会发现自动跳转到一个登录页面

为了登录系统，我们需要知道用户名密码，spring security 默认的用户名是user，spring security启动的时候会生成默认密码（在启动日志中可以看到）。本例，我们指定一个用户名密码，在配置文件中加入如下内容：

    security.user.name=admin
    security.user.password=admin

重启项目，访问被保护的/hello页面。自动跳转到了spring security 默认的登录页面，我们输入用户名admin密码admin。点击Login按钮。会发现登录成功并跳转到了/hello。除了登录，spring security还提供了rememberMe功能，这里不做过多解释。

### 角色-资源 访问控制

通常情况下，我们需要实现“特定资源只能由特定角色访问”的功能。假设我们的系统有如下两个角色：

* ADMIN 可以访问所有资源
* USER 只能访问特定资源
现在我们给系统增加“/product” 代表商品信息方面的资源（USER可以访问）；增加"/admin"代码管理员方面的资源（USER不能访问）。代码如下：


        @Controller
        @RequestMapping("/product")
        public class ProductTestController {
        
            @RequestMapping("/info")
            @ResponseBody
            public String productInfo(){
                return " some product info ";
            }
        }
        -------------------------------------------
        @Controller
        @RequestMapping("/admin")
        public class AdminTestController {
        
            @RequestMapping("/home")
            @ResponseBody
            public String productInfo(){
                return " admin home page ";
            }
        }

在正式的应用中，我们的用户和角色是保存在数据库中的；本例为了方便演示，我们来创建两个存放于内存的用户和角色。我们在上一步中创建的SecurityConfiguration中增加角色用户，如下代码：

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("admin1") // 管理员，同事具有 ADMIN,USER权限，可以访问所有资源
                    .password("{noop}admin1")  // 
                    .roles("ADMIN", "USER")
                    .and()
                .withUser("user1").password("{noop}user1") // 普通用户，只能访问 /product/**
                    .roles("USER");
    }
这里，我们增加了 管理员（admin1，密码admin1），以及普通用户（user1,密码user1）

继续增加“链接-角色”控制配置，代码如下:


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				    .antMatchers("/product/**").hasRole("USER")
				    .antMatchers("/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated()
				.and()
				.formLogin().and()
				.httpBasic();
	}
	
	
这个配置在上一步中登录配置的基础上增加了链接对应的角色配置。上面的配置，我们可以知道：

* 使用 user1 登录，只能访问/product/**
* 使用 admin1登录，可以访问所有。


下面来验证一下普通用户登录，重启项目，在浏览器中输入：http://localhost:8080/admin/home。同样，我们会到达登录页面，我们输入用户名user1,密码也为user1 结果错误页面了，拒绝访问了，信息为：


    There was an unexpected error (type=Forbidden, status=403).
    Access is denied

我们把浏览器中的uri修改成：/product/info，结果访问成功。可以看到some product info。说明 user1只能访问 product/** ,这个结果与我们预期一致。

再来验证一下管理员用户登录，重启浏览器之后，输入http://localhost:8080/admin/home。在登录页面中输入用户名admin1，密码admin1，提交之后，可以看到admin home page ,说明访问管理员资源了。我们再将浏览器uri修改成/product/info,刷新之后，也能看到some product info,说明 admin1用户可以访问所有资源，这个也和我们的预期一致。
