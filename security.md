

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






























[spring security 干货](https://www.felord.cn/categories/spring-security/)

#### 1. Spring Boot 集成 Spring Security

这个简直老生常谈了。不过为了照顾大多数还是说一下。集成 Spring Security 只需要引入其对应的 Starter 组件。Spring Security 不仅仅能保护Servlet Web 应用，也可以保护Reactive Web应用，本文我们讲前者。我们只需要在 Spring Security 项目引入以下依赖即可：


    <dependencies>
        <!--  actuator 指标监控  非必须 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <!--  spring security starter 必须  -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!-- spring mvc  servlet web  必须  -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!--   lombok 插件 非必须       -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <!-- 测试   -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
#### 2. UserDetailsServiceAutoConfiguration

启动项目，访问Actuator端点http://localhost:8080/actuator会跳转到一个登录页面http://localhost:8080/login


要求你输入用户名 Username （默认值为user）和密码 Password 。密码在springboot控制台会打印出类似 Using generated security password: e1f163be-ad18-4be1-977c-88a6bcee0d37 的字样，后面的长串就是密码，当然这不是生产可用的。如果你足够细心会从控制台打印日志发现该随机密码是由UserDetailsServiceAutoConfiguration 配置类生成的，我们就从它开始顺藤摸瓜来一探究竟。

#### 2.1 UserDetailsService

UserDetailsService接口。该接口只提供了一个方法：

  UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
该方法很容易理解：通过用户名来加载用户 。这个方法主要用于从系统数据中查询并加载具体的用户到Spring Security中。

#### 2.2 UserDetails

从上面UserDetailsService 可以知道最终交给Spring Security的是UserDetails 。该接口是提供用户信息的核心接口。该接口实现仅仅存储用户的信息。后续会将该接口提供的用户信息封装到认证对象Authentication中去。UserDetails 默认提供了：

* 用户的权限集， 默认需要添加ROLE_ 前缀
* 用户的加密后的密码， 不加密会使用{noop}前缀
* 应用内唯一的用户名
* 账户是否过期
* 账户是否锁定
* 凭证是否过期
* 用户是否可用

如果以上的信息满足不了你使用，你可以自行实现扩展以存储更多的用户信息。比如用户的邮箱、手机号等等。通常我们使用其实现类：

    org.springframework.security.core.userdetails.User

该类内置一个建造器UserBuilder 会很方便地帮助我们构建UserDetails 对象，后面我们会用到它。

#### 2.3 UserDetailsServiceAutoConfiguration

UserDetailsServiceAutoConfiguration 全限定名为:

    org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration
源码如下：

    @Configuration
    @ConditionalOnClass(AuthenticationManager.class)
    @ConditionalOnBean(ObjectPostProcessor.class)
    @ConditionalOnMissingBean({ AuthenticationManager.class, AuthenticationProvider.class, UserDetailsService.class })
    public class UserDetailsServiceAutoConfiguration {
    
        private static final String NOOP_PASSWORD_PREFIX = "{noop}";
    
        private static final Pattern PASSWORD_ALGORITHM_PATTERN = Pattern.compile("^\\{.+}.*$");
    
        private static final Log logger = LogFactory.getLog(UserDetailsServiceAutoConfiguration.class);
    
        @Bean
        @ConditionalOnMissingBean(
                type = "org.springframework.security.oauth2.client.registration.ClientRegistrationRepository")
        @Lazy
        public InMemoryUserDetailsManager inMemoryUserDetailsManager(SecurityProperties properties,
                ObjectProvider<PasswordEncoder> passwordEncoder) {
            SecurityProperties.User user = properties.getUser();
            List<String> roles = user.getRoles();
            return new InMemoryUserDetailsManager(
                    User.withUsername(user.getName()).password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
                            .roles(StringUtils.toStringArray(roles)).build());
        }
    
        private String getOrDeducePassword(SecurityProperties.User user, PasswordEncoder encoder) {
            String password = user.getPassword();
            if (user.isPasswordGenerated()) {
                logger.info(String.format("%n%nUsing generated security password: %s%n", user.getPassword()));
            }
            if (encoder != null || PASSWORD_ALGORITHM_PATTERN.matcher(password).matches()) {
                return password;
            }
            return NOOP_PASSWORD_PREFIX + password;
        }
    
    }
我们来简单解读一下该类，从@Conditional系列注解我们知道该类在类路径下存在AuthenticationManager、在Spring 容器中存在Bean ObjectPostProcessor并且不存在Bean AuthenticationManager, AuthenticationProvider, UserDetailsService的情况下生效。千万不要纠结这些类干嘛用的! 该类只初始化了一个UserDetailsManager 类型的Bean。UserDetailsManager 类型负责对安全用户实体抽象UserDetails的增删查改操作。同时还继承了UserDetailsService接口。

明白了上面这些让我们把目光再回到UserDetailsServiceAutoConfiguration 上来。该类初始化了一个名为InMemoryUserDetailsManager 的内存用户管理器。该管理器通过配置注入了一个默认的UserDetails存在内存中，就是我们上面用的那个user ，每次启动user都是动态生成的。那么问题来了如果我们定义自己的UserDetailsManager Bean是不是就可以实现我们需要的用户管理逻辑呢？

#### 2.4 自定义UserDetailsManager

我们来自定义一个UserDetailsManager 来看看能不能达到自定义用户管理的效果。首先我们针对UserDetailsManager 的所有方法进行一个代理的实现，我们依然将用户存在内存中，区别就是这是我们自定义的：

    package cn.felord.spring.security;
    
    import org.springframework.security.access.AccessDeniedException;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    
    import java.util.HashMap;
    import java.util.Map;
    
    /**
     * 代理 {@link org.springframework.security.provisioning.UserDetailsManager} 所有功能
     *
     * @author Felordcn
     */
    public class UserDetailsRepository {
    
        private Map<String, UserDetails> users = new HashMap<>();
    
    
        public void createUser(UserDetails user) {
            users.putIfAbsent(user.getUsername(), user);
        }
    
    
        public void updateUser(UserDetails user) {
            users.put(user.getUsername(), user);
        }
    
    
        public void deleteUser(String username) {
            users.remove(username);
        }
    
    
        public void changePassword(String oldPassword, String newPassword) {
            Authentication currentUser = SecurityContextHolder.getContext()
                    .getAuthentication();
    
            if (currentUser == null) {
                // This would indicate bad coding somewhere
                throw new AccessDeniedException(
                        "Can't change password as no Authentication object found in context "
                                + "for current user.");
            }
    
            String username = currentUser.getName();
    
            UserDetails user = users.get(username);
    
    
            if (user == null) {
                throw new IllegalStateException("Current user doesn't exist in database.");
            }
    
            // todo copy InMemoryUserDetailsManager  自行实现具体的更新密码逻辑
        }
    
    
        public boolean userExists(String username) {
    
            return users.containsKey(username);
        }
    
    
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            return users.get(username);
        }
    }
该类负责具体对UserDetails 的增删改查操作。我们将其注入Spring 容器：

    @Bean
    public UserDetailsRepository userDetailsRepository() {
        UserDetailsRepository userDetailsRepository = new UserDetailsRepository();

        // 为了让我们的登录能够运行 这里我们初始化一个用户Felordcn 密码采用明文 当你在密码12345上使用了前缀{noop} 意味着你的密码不使用加密，authorities 一定不能为空 这代表用户的角色权限集合
        UserDetails felordcn = User.withUsername("Felordcn").password("{noop}12345").authorities(AuthorityUtils.NO_AUTHORITIES).build();
        userDetailsRepository.createUser(felordcn);
        return userDetailsRepository;
    }
为了方便测试 我们也内置一个名称为Felordcn 密码为12345的UserDetails用户，密码采用明文 当你在密码12345上使用了前缀{noop} 意味着你的密码不使用加密，这里我们并没有指定密码加密方式你可以使用PasswordEncoder 来指定一种加密方式。通常推荐使用Bcrypt作为加密方式。默认Spring Security使用的也是此方式。authorities 一定不能为null 这代表用户的角色权限集合。接下来我们实现一个UserDetailsManager 并注入Spring 容器：

    @Bean
    public UserDetailsManager userDetailsManager(UserDetailsRepository userDetailsRepository) {
        return new UserDetailsManager() {
            @Override
            public void createUser(UserDetails user) {
                userDetailsRepository.createUser(user);
            }

            @Override
            public void updateUser(UserDetails user) {
                userDetailsRepository.updateUser(user);
            }

            @Override
            public void deleteUser(String username) {
                userDetailsRepository.deleteUser(username);
            }

            @Override
            public void changePassword(String oldPassword, String newPassword) {
                userDetailsRepository.changePassword(oldPassword, newPassword);
            }

            @Override
            public boolean userExists(String username) {
                return userDetailsRepository.userExists(username);
            }

            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return userDetailsRepository.loadUserByUsername(username);
            }
        };
    }
这样实际执行委托给了UserDetailsRepository 来做。我们重复 章节3. 的动作进入登陆页面分别输入Felordcn和12345 成功进入。

#### 2.5 数据库管理用户

经过以上的配置，相信聪明的你已经知道如何使用数据库来管理用户了 。只需要将 UserDetailsRepository 中的 users 属性替代为抽象的Dao接口就行了，无论你使用Jpa还是Mybatis来实现。

#### 3. 总结
 
今天我们对Spring Security 中的用户信息 UserDetails 相关进行的一些解读。并自定义了用户信息处理服务。相信你已经对在Spring Security中如何加载用户信息，如何扩展用户信息有所掌握了。后面我们会由浅入深慢慢解读Spring Security。相关代码已经上传git仓库,关注公众号Felordcn 后回复ss01 获取demo源码。 后续也可以及时
