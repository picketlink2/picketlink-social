<%@ page import="org.picketlink.social.reg.UserRegistration" %>

<%
  String fullName = request.getUserPrincipal().getName();
  String email = null;
  UserRegistration user = (UserRegistration)session.getAttribute("user");
  if(user != null)
  {
    fullName = user.getFirstName() + " " + user.getLastName();
    email = user.getEmail();
  }
%>
   
<html>
<body>

<div align="center">
<h1>PicketLink Social Registration</h1>
<br/>
Welcome <%=fullName%>

<br/>
Your email address is:<%=email%>

<br/>

</div>
