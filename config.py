
login_url='http://localhost/scarf/login.php'
logout_url='http://localhost/scarf/login.php?logout=1'
username='email'
password='password'
roles=2
#login_url='http://localhost:8000/login/'
#logout_url='http://localhost:8000/logout/'
#username='username'
#password='password'
#roles=1
#login_url='http://localhost/users/login.php'
#logout_url='http://localhost/users/logout.php'
#username='username'
#password='password'
#roles=1
#login_url='http://localhost/openit/login.php'
#logout_url='http://localhost/openit/logout.php'
#username='Employee'
#password='Password'
#roles=1
def get_configuration():
	return login_url,logout_url,username,password,roles

