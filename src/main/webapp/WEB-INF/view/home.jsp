<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>

<html>

    <head>
    <title>Arena</title>
    </head>
    
    <body>
        <h2>Magic the Gathering Battle Arena</h2>
        <hr>
        
        <p>
        Welcome to the MTG battle arena!
        </p>
        
        <hr>
        
        <!-- Displaying the user ID -->
        
        <p>
            User: <security:authentication property="principal.username" />
            <br><br>
            Role(s): <security:authentication property="principal.authorities" />
        </p>
        
        <security:authorize access="hasRole('PLAINSWALKER')">
                
        <hr>
        
            <!-- Add a link to point to /leaders ... this is for plainswalkers -->
        
            <p>
                <a href="${pageContext.request.contextPath}/leaders">Plainswalkers meeting</a>
                (Only for Plainswalkers!)
        
            </p>
        </security:authorize>
        
        <security:authorize access="hasRole('DRAGON')">
                                
        <hr>
            <!-- Adding a link for access to /systems .. this is for dragons -->
        
            <p>
                <a href="${pageContext.request.contextPath}/systems">Dragons Eye Peek</a>
                (Dragons only!)
        
            </p>
        </security:authorize>
        
        <hr>
        
        <!-- Add a logout button -->
        <form:form action="${pageContext.request.contextPath }/logout" method="POST">
        
            <input type="submit" value="Logout" />
        </form:form>
        
    </body>

</html>