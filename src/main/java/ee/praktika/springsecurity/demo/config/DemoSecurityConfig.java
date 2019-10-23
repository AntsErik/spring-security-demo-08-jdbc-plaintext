package ee.praktika.springsecurity.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure( AuthenticationManagerBuilder auth ) throws Exception{

        //add users to in memory authentication

        UserBuilder users = User.withDefaultPasswordEncoder();

        auth.inMemoryAuthentication()
            .withUser( users.username( "Liliana" ).password( "MTG247" ).roles( "PLAINSWALKER", "CREATURE" ) )
            .withUser( users.username( "Ugin" ).password( "MTG247" ).roles( "DRAGON", "PLAINSWALKER", "CREATURE" ) )
            .withUser( users.username( "Suntail Hawk" ).password( "MTG247" ).roles( "CREATURE", "BIRD" ) );
    }

    @Override
    protected void configure( HttpSecurity http ) throws Exception{

        http.authorizeRequests()
            .antMatchers( "/" ).permitAll() // allow public access to home page
            .antMatchers( "/employees" ).hasRole( "CREATURE" )
            .antMatchers( "/leaders/**" ).hasRole( "PLAINSWALKER" )
            .antMatchers( "/systems/**" ).hasRole( "DRAGON" )
            .and()
            .formLogin()
            .loginPage( "/showMyLoginPage" ) //Show our custom form at the request mapping
            .loginProcessingUrl( "/authenticateTheUser" ) //Login form should POST data to this URL for processing - (check user id and password)
            .permitAll() //Allow everyone to see the login page. No need to be logged in for that.
            .and()
            .logout()
            .logoutSuccessUrl( "/" ) // after logout then redirect to landing page (root)
            .permitAll() //adds logout permission
            .and()
            .exceptionHandling().accessDeniedPage( "/access-denied" ); //custom access denied page
    }
}
