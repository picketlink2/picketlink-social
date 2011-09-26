<html>
<head>
<meta charset="utf-8" />
<title>PicketLink Social Registration</title>
<link rel="stylesheet" href="css/reset.css" />
<link rel="stylesheet" href="css/text.css" />
<link rel="stylesheet" href="css/960.css" />
<link rel="stylesheet" href="css/demo.css" />
</head>

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

<body>
<div class="container_12">
  <h2>
    PicketLink Social Registration
  </h2>
  <div class="grid_12">
    <img src="images/picketlink_banner.png"/>
  </div>
  <!-- end .grid_12 -->
  <div class="clear"></div>
  <div class="grid_12">
    <div class="grid_3"/>
    <div class="grid_6">
    <p>
    Welcome <%=fullName%>
    </p>
    <p>
    Your email address is:<%=email%>
    </p>
    </div>
    <div class="grid_3"/>
  </div>
  </div>
  <!-- end .grid_11 -->
  <div class="clear"></div>
</div>

</body>
</html>
