package ee.praktika.springsecurity.demo.config;

import java.beans.PropertyVetoException;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import com.mchange.v2.c3p0.ComboPooledDataSource;

@Configuration
@EnableWebMvc
@ComponentScan( basePackages = "ee.praktika.springsecurity.demo" )
@PropertySource( "classpath:persistence-mysql.properties" )
public class DemoAppConfig {

    //set up a variable to hold the properties
    @Autowired
    private Environment env; //helper class that will hold data that is read from the properties file

    //set up a logger for some diagnostics    
    private Logger logger = Logger.getLogger( getClass().getName() );

    //define a bean for ViewResolver

    @Bean
    public ViewResolver viewResolver(){

        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();

        viewResolver.setPrefix( "/WEB-INF/view/" );
        viewResolver.setSuffix( ".jsp" );

        return viewResolver;
    }

    //define a bean for security data source
    @Bean
    public DataSource securityDataSource(){

        //create a connection pool
        ComboPooledDataSource securityDataSource = new ComboPooledDataSource();

        //set the jdbc driver class
        try {
            securityDataSource.setDriverClass( env.getProperty( "jdbc.driver" ) );
        }
        catch( PropertyVetoException exc ) {
            throw new RuntimeException( exc );
        }

        //log some of the connection properties
        logger.info( ">>> jdbc.url=" + env.getProperty( "jdbc.url" ) );
        logger.info( ">>> jdbc.user=" + env.getProperty( "jdbc.user" ) );

        //setupp the database connection props
        securityDataSource.setJdbcUrl( env.getProperty( "jdbc.url" ) );
        securityDataSource.setUser( env.getProperty( "jdbc.user" ) );
        securityDataSource.setPassword( env.getProperty( "jdbc.password" ) );

        //finally set up connection pool properties
        //securityDataSource.setInitialPoolSize( initialPoolSize );
        securityDataSource.setInitialPoolSize(
            getIntProperty( "connection.pool.initialPoolSize" ) );

        securityDataSource.setMinPoolSize(
            getIntProperty( "connection.pool.minPoolSize" ) );

        securityDataSource.setMaxPoolSize(
            getIntProperty( "connection.pool.maxPoolSize" ) );

        securityDataSource.setMaxIdleTime(
            getIntProperty( "connection.pool.maxIdleTime" ) );

        return securityDataSource;
    }

    //need a helper method for parsing - read environment property and convert to int
    private int getIntProperty( String propName ){

        String propVal = env.getProperty( propName );

        // now convert to int
        int intPropVal = Integer.parseInt( propVal );

        return intPropVal;
    }
}
