<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Whitelist Manager</title>
	
	<link rel="stylesheet" type="text/css" href="CSS/home.css" />
	
	<script type="text/javascript" src="Scripts/JQuery/jquery-1.7.2.js"></script>
	<script type="text/javascript" src="Scripts/commonUtils.js"></script>
	<script type="text/javascript" src="Scripts/login.js"></script>

</head>
<body>
	<div> <!-- For customer Customized page, remove this class -->
	<div class="header"><!-- For customer Customized page , change this to header provided by customer-->
       <div class="title"><h1>OAT Whitelist Manager</h1></div>
            <div class="clear hideSkiplink">
				<div style="clear: left;"></div><a id="NavigationMenu_SkipLink"></a>
            </div>
        </div>
        </div>
        <div class="main" id="mainContainer">
	        <div class="container">
				<div id="nameOfPage" class="NameHeader">Login</div>
                                <div class="registerUser">Press login to continue</div>
				
				<form id="loginForm" action="checkLogin.htm" method="post" style="margin-left: 60px;font-size: 16px;">
					<table cellpadding="3" cellspacing="5">
                 	<tbody>
	                	<tr>
                 			<td ><label></label></td>
	                    	<td><input type="submit" class="button" value="Login"></td>
	                    	<td></td>
	                    </tr>
	                </tbody>
                </table>
				</form>
				<div class="errorMessage">${message}</div>
        	</div>
        </div>
        <div class="footer">
        	<h4>@ Intel Corp | 2013</h4><!-- For customer Customized page, will be provided by customer -->
        </div>
        
        
</body>
</html>