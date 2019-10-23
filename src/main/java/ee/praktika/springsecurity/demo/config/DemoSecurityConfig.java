package ee.praktika.springsecurity.demo.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

    //add a reference to our security data source
    @Autowired
    private DataSource securityDataSource;

    @Override
    protected void configure( AuthenticationManagerBuilder auth ) throws Exception{

        //use jdbc authentication
        auth.jdbcAuthentication().dataSource( securityDataSource ); //Telling Spring Security to use JDBC authentication with our data source, no hard coding users!
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
