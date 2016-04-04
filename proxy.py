import socket, thread, select
import re
from phpserialize import *
import base64
#import psycopg2
import time
import os
from subprocess import Popen, PIPE, STDOUT
import sys
#import state
#import graph
import json
import pickle
from models import State,transition,role
from dom import html_compare
from bs4 import BeautifulSoup
from hotqueue import HotQueue
from config import get_configuration



global_session=''
__version__ = '0.1.0 Draft 1'
BUFLEN = 8192
VERSION = 'Python Proxy/'+__version__
HTTPVER = 'HTTP/1.1'
states=set([])
current=''
prev=''
ses=""
output=""
sequence={}
session={}
html_response={}
stop=False
login={}
temp_login_info=[]
param_info={}
params={}
current_cookie=''
current_cookie_decoded=''
new_request=1
server=''
server_set=False
data_pool=''
#login_url='http://localhost/openit/login.php'
#logout_url='http://localhost/openit/logout.php'
#login_url='http://localhost/scarf/login.php'
#logout_url='http://localhost/scarf/login.php?logout=1'
#login_url='http://localhost/users/login.php'
#logout_url='http://localhost/users/logout.php'
#login_field=' '
#login_pass_field=' '
login_url,logout_url,login_field,login_pass_field,num_roles=get_configuration()
s=[]
state_set=[]
transition_set=[]
authorized=False
role_set=[]
role_id=0
f=open("requests.txt",'w')
'''
This function unserializes and decodes the value inside a PHP session file
'''

         
        
def unserialize_session(val):
        if not val:
                return "1"
        session = {}
        #print val[0]
        groups = re.split('([a-zA-Z0-9_]+)\|', val[0])
        #print groups
        if len(groups) > 2:
                groups = groups[1:]
                groups = map(None, *([iter(groups)] * 2))
    
                for i in range(len(groups)):
                        session[groups[i][0]] = loads(groups[i][1])
        #print "$$$$$$$$$$$$$$$$",type(session)
        return session


def decode_java_session(val):
	final=val.split("t")
	#print final
	d=[]
	if len(final)==1:
		return '1'
	dictionary={}
	for i in range(1,len(final)):
		#print final[i]
		final[i]=final[i][2:]
		#print final[i]
		d.append(final[i])
	d[-1]=d[-1][:-3]
	for i in range(len(d)):
		if(i%2==0):
			dictionary[d[i]]=d[i+1]

	#print dictionary
	return dictionary



def extract_server(data):
	global server
	server_line=''
	server=re.search("X-Powered-By:(.+?)\r",data)
	if server:
		server_line=server.group(0)
		#print server_line
	else:
		server=re.search("Server:(.+?)\r",data)
		if server:
			server_line=server.group(0)
			#print server_line
		else:
			server_line=""
	if server_line!='':
		#print server_line
		if 'PHP' in server_line:
			server='PHP'
		if re.search("Python",server_line):
			server='Python'
		if re.search("JSP",server_line):
			server='JSP'
		if re.search("Ruby",server_line):
			server='Ruby'
		return True
	return False

def extract_php_session(data,url):
					global ses
        				global current
        				global prev
        				global sequence
        				global session
        				global stop
					global new_request
					global server
					global login
					global temp_login_info
					global param_info
					global login_url,logout_url
					global s
					global role_set,role_id,authorized,global_session
					output=''
					
                                        if url==logout_url:
                                                stop=True
					
                                        m = re.search('Set-Cookie', data)
                                        if m:
                                                                          
                                                m = re.search('PHPSESSID=(.+?);', data)
						#m = re.search('OpenITSessionID=(.+?);', data)
                                                output=""
                                        
                                                if m:
							
                                                        ses=str(m.group(1))
                                                try:
                                                        files=open("/opt/lampp/temp/sess_"+ses,'r')
                                                        
                                                        dat=files.readlines()
                                                        output+= url+ "    |       "+ses+" |       "
                                                        t=unserialize_session(dat)
							output+= str(unserialize_session(dat))
                                                        output+=t[1:-1]+"\n"
                                                        
							if len(temp_login_info) !=0:
								#print 'BOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOm'
								for i in t.keys():
									login[t[i]]=temp_login_info
								if authorized:
									role_set.append(role(role_id,temp_login_info,t))
								temp_login_info=[]
							if url==logout_url:
								t='1'
							global_session=[t]
							
							
                                                        
                                                except IOError as e:
                                                        output+=url+ "     |       NULL    |       NULL"+ "\n"
                                                        print e
                                                
                                        elif ses!='':
						
                                                try:
							if url==logout_url:
								t='1'
							else:
                                                        	files=open("/opt/lampp/temp/sess_"+ses,'r')
                                                        	#files=open("C://xampp/tmp/sess_"+ses,'r')
                                                        	dat=files.readlines()
                                                        	output+= url+ "    |       "+ses+" |       "
                                                        	t=unserialize_session(dat)
                                                        
                                                        	output+= str(unserialize_session(dat))+"\n"
							
							if len(temp_login_info) !=0:
								#print 'BOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOm'
								for i in t.keys():
									login[t[i]]=temp_login_info
								if authorized:								
									role_set.append(role(role_id,temp_login_info,t))
									
								temp_login_info=[]
							global_session=[t]
							
                                                        
                                                except IOError as e:
                                                        output+=url+ "     |       NULL    |       NULL"+ "\n"
                                                        print e
                                                
					
def extract_python_session(data,url):
					global ses
        				global current
        				global prev
        				global sequence
        				global session
        				global stop
					global new_request
					global server
					global login,global_session
					global temp_login_info
					#print 'In python'
					#print data
					output=''					
					
                                        if url==logout_url:
                                                stop=True
						#print 'Seen logout url'
                                	m = re.search('Set-Cookie', data)       
					#print ses                
                                	if m and ses=='':
                                        	#print 'Setcookie found'
                                        	#print data
						#print self.url
                                        	m = re.findall('sessionid=(.+?);',data)
                                        	output=""
                                        	#print m
                                        	if m:
                                                	ses=m[0]
                                                
                                                	try:
								#print 'abt to do it'
                                                        	files=open("/tmp/sessionid"+ses,'r')
                                                        	dat=files.readlines()[0]
                                                        	#print dat
                                                        	output+=url+"   |   "+base64.b64decode(dat)+"\n"
								#print base64.b64decode(dat)
								data=base64.b64decode(dat).split(':',1)[1]
								#print data
								t=json.loads(data)
								#print t
								if len(temp_login_info) !=0:
									#print 'BOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOm'
									for i in t.keys():
										login[t[i]]=temp_login_info
								
									temp_login_info=[]
								if t=={} or url==login_url:
									t='1'
								global_session=[t]
                                                        	
                                                        	#print session
								
                                                	except IOError as e:
                                                        	output+=url+ "     |       NULL    |       NULL"+ "\n"
                                                        	print "Error:",e
                                                	#print output
                                        
                                                	
					elif ses!='':
						#print "Session already known..."
						try:
                                                        files=open("/tmp/sessionid"+ses,'r')
                                                        dat=files.readlines()[0]
                                                        #print dat
                                                        output+=url+"   |   "+base64.b64decode(dat)+"\n"
                                                	
                                        		data=base64.b64decode(dat).split(':',1)[1]
							#print data
							t=json.loads(data)
							if len(temp_login_info) !=0:
								for i in t.keys():
									login[t[i]]=temp_login_info
								
								temp_login_info=[]
							if t=={} or url==login_url:
								t='1'
							global_session=[t]
                                                        
							
						except IOError as e:
                                                        output+=url+ "     |       NULL    |       NULL"+ "\n"
							if url==logout_url:
								t='1'
								
                                                        

def extract_ruby_session(data,url):
					global ses
        				global current
        				global prev
        				global sequence
        				global session
        				global stop
					global new_request
					global server
					global login
					global temp_login_info
					global current_cookie_decoded
					global login_url,logout_url
					#print 'In ruby'
					#print data
					output=''
					prev=current
                                        current=url
                                        #sequence[prev]=current
                                        #print sequence
					if prev not in sequence:
						sequence[prev]=[current]
					else:
						if current not in sequence[prev]:
							sequence[prev].append(current)
                                        states.add(url)
                                        if url==logout_url:
                                                stop=True
                                        #print states
                                        #print "Previous State:",prev
                                        #print "Current State:",current
					m=re.search('Cookie: (_.+?)=(.+?)\r',data)
					if m:
						#print "here", url
						ses=str(m.group(1))
						t=ses+'=(.+?)\r'
						# For stroing Cookie value
						m=re.search(t,data)
						ses=str(m.group(1))
						if ses.find('--')!=-1:
							# For decoding control transfers to other file
							decd = Popen(['ruby', 'dec.rb'], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
							result=[]
							decd.stdin.write(ses+'\n')
							# Reading decoded value 
							ses= decd.stdout.readline().rstrip()
							# Storing decoded value
							result.append(ses)
							#print type(result)
							for i in result:
								pass
								#print type(i)
								#print i
							d={}
							l=result[0].split(",")
							#print l
							for i in range(2,len(l)):
								l1= l[i].split("=>")
								for j in range(len(l1)):
									if j%2==0:
										a=re.findall('\"(.+?)\"',l1[j])[0]
										b=re.findall('\"(.+?)\"',l1[j+1])[0]
										d[a]=b
							#print d
							#session[current]=d	
							#print '\n'.join(result)
							t=d
							if t=={}:
								t='1'
							current_cookie_decoded=t
							#print "Current cookie=",str(t)
							#session[current]=d	
							#print '\n'.join(result)
							#print "done somethings"
							if len(temp_login_info) !=0:
								login[t[t.keys()[0]]]=temp_login_info
								#print 'Login info set!!!'
								temp_login_info=[]
                                                        if current not in session:
								session[current]=[t]
								print '\nURL:',url
								print 'Session:',str(t)
								if param_info!={}:
									print 'Parameters:',str(param_info)
									params[current]=param_info
								#session[current]=session[current].append(t)
							elif not url==login_url and t not in session[current]:
                                                        	session[current].append(t)
								print '\nURL:',url
								print 'Session:',str(t)
								if param_info!={}:
									print 'Parameters:',str(param_info)
									params[current]=param_info
					else:
						if current_cookie_decoded!='':
							t=current_cookie_decoded
							#print "Taking current cookie",str(t)
							#session[current]=d	
							#print '\n'.join(result)
							#print "done somethings"
							if len(temp_login_info) !=0:
								login[t[t.keys()[0]]]=temp_login_info
								#print 'Login info set!!!'
								temp_login_info=[]
                                                        if current not in session:
								session[current]=[t]
								print '\nURL:',url
								print 'Session:',str(t)
								if param_info!={}:
									print 'Parameters:',str(param_info)
									params[current]=param_info
								#session[current]=session[current].append(t)
							elif not url==login_url and t not in session[current]:
                                                        	session[current].append(t)
								print '\nURL:',url
								print 'Session:',str(t)
								if param_info!={}:
									print 'Parameters:',str(param_info)
									params[current]=param_info


                			
def extract_java_session(data,url):
					global ses
        				global current
        				global prev
        				global sequence
        				global session
        				global stop
					global new_request
					global server
					global login
					global temp_login_info
					#print 'In java'
					output=''
					prev=current
                                        current=url
					
                                        if prev not in sequence:
						sequence[prev]=[[current,session[prev]]]
					else:
						if current not in sequence[prev]:
							sequence[prev].append([current,session[prev]])
                                        #print sequence
                                        states.add(url)
                                        if url==logout_url:
						#print 'Found logout URL'
                                                stop=True
                                        #print states
                                        #print "Previous State:",prev
                                        #print "Current State:",current
					m = re.findall('JSESSIONID=(.+?);',data)
                                        output=""
                                        #print m
                                        if m:
							#print 'Got in fine'
                                              		ses=m[0]
                                              		#print m
                                                        #print ses
                                                        try:
								while not os.path.isfile("/home/amit/Desktop/"+ses+".session"):
									pass
								time.sleep(2)
                                                                files=open("/home/amit/Desktop/"+ses+".session",'r')
                                                                dat=files.readlines()
                                                                #print dat[-1]
								t=decode_java_session(dat[-1].split(ses)[1])
								#print t
								#session[current]=t
                                                                output+=url+"   |   "+str(t)+"\n"
								if len(temp_login_info) !=0:
									login[t[t.keys()[0]]]=temp_login_info
									#print 'Login info set!!!'
									temp_login_info=[]
                                                        	if current not in session:
									session[current]=[t]
									print '\nURL:',url
									print 'Session:',str(t)
									#session[current]=session[current].append(t)
								elif not url==login_url and t not in session[current]:
									#print 'Added here...'
                                                        		session[current].append(t)
									print '\nURL:',url
									#print 'Session:',str(t)
                                                        	#print session
								if param_info!={}:
									print 'Parameters:',str(param_info)
									if url!=login_url:
										params[current]=param_info
                                                        except IOError as e:
                                                                output+=url+ "     |       NULL    |       NULL"+ "\n"
                                                                #print "Error:",e
                                                        #print output
                                                
                                                        fi=open("result.txt",'w')
                                                        fi.write(output)
                                                        fi.close()
					elif ses!='':
							#print 'Im in'
							try:
								while not os.path.isfile("/home/amit/Desktop/"+ses+".session"):
									pass
								time.sleep(30)
                                                                files=open("/home/amit/Desktop/"+ses+".session",'r')
                                                                dat=files.readlines()
                                                                #print dat[-1]
								t=decode_java_session(dat[-1].split(ses)[1])
								#print t
								#session[current]=t
                                                                output+=url+"   |   "+str(t)+"\n"
								if len(temp_login_info) !=0:
									login[t[t.keys()[0]]]=temp_login_info
									#print 'Login info set!!!'
									temp_login_info=[]
                                                        	if current not in session:
									session[current]=[t]
									print '\nURL:',url
									print 'Session:',str(t)
									if param_info!={}:
										print 'Parameters:',str(param_info)
										if url!=login_url:
											params[current]=param_info
									#session[current]=session[current].append(t)
								elif not self.url==login_url and t not in session[current]:
									#print 'Added here...'
                                                        		session[current].append(t)
									print '\nURL:',url
									print 'Session:',str(t)
									if param_info!={}:
										print 'Parameters:',str(param_info)
										if url!=login_url:
											params[current]=param_info
                                                        	#print session
								
                                                        except IOError as e:
                                                                output+=url+ "     |       NULL    |       NULL"+ "\n"
                                                                print "Error:",e
                                                        #print output
					#print 'Done'
                                                
def extract_url_params(url):
	global param_info
	param={}
	param_string=url.split('?')[1]
	param_list=param_string.split('&')
	for item in param_list:
		param[item.split('=')[0]]=item.split('=')[1]
	param_info['GET']=param
	
def validate(url):
	invalid_list=[".css",".js",".png",".jpg",".ico",".gif",".swf"]
	for ext in invalid_list:
		if ext in url:
			return False
	return True

def existsState(current,html):
	'''
	global state_set,state_id,login_url,logout_url
	for x in state_set:
		if x.url==current:
			if current==login_url or current==logout_url:
				return True,x
			if html_compare(html,x.dom):
				#print 'Same dom found for ',x.url
				return True,x
	'''
	return False,None


def compare(p,p1):
	flag=False 
	if p==None and p1==None:
		return True
	elif p==None or p1==None:
		return False
	if set(p.keys())==set(p1.keys()):
		if 'GET' in p.keys():
			flag=False
			if set(p['GET'])==set(p1['GET']):
				flag=True
			else:
				return flag
		if 'POST' in p.keys():
			flag=False
			if set(p['POST'])==set(p1['POST']):
				flag=True
	return flag
			

def checkAndAddTransition(source,dest,sess,param):
	
	global transition_set
	flag=0
	
	cur=source
	#print 'Checking.......'
	#print dest.url
	#print sess
	#print 'Done checking'
	for i in range(len(transition_set)):
		x=transition_set[i] 
		
		if x.source==cur and x.dest==dest and x.session==sess and compare(x.params,param):
			flag=1
			break
		elif x.source==cur and x.dest==dest and compare(x.params,param):
			transition_set[i].addSession(sess)
			
			#print 'Extending'
			flag=1
			break
	if flag==0:
		transition_set.append(transition(source,dest,sess,param))
		#print 'appended to transition set'
		#print transition_set[-1]
		#print transition_set[-1].dest.url
		#print transition_set[-1].session
		#print 'Done'
			
			

class ConnectionHandler:
    def __init__(self, connection, address, timeout):
        #print "Building a new object",address
        self.client = connection
        self.client_buffer = ''
        self.timeout = timeout
        self.url=''
        self.method, self.path, self.protocol = self.get_base_header()
	#print self.path
	if '127.0.0.1' in self.path:
		helloworld(self.client_buffer, self.path)
        	if self.method=='CONNECT':
            		self.method_CONNECT()
        	elif self.method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT',
                	             'DELETE', 'TRACE'):
            		self.method_others()
        	self.client.close()
        	self.target.close()
	#print "I am done"
	
   
    def get_base_header(self):
        global ses
	global new_request
	global data_pool
	global html_response
	global current,prev
        output=''
        #print "In getbaseheader function"
        while 1:
                self.client_buffer += self.client.recv(BUFLEN)
                end = self.client_buffer.find('\n')
                if end!=-1:
                        break
	#print "Getting a new request..."
	#print 'Current URL:',current
	if current!='' and '<html' in data_pool:
		#print "Stroing response"
		html_response[current]='<html'+data_pool.split('<html')[1]
        first_line = self.client_buffer.split('\n')[0]
        self.url = first_line.split(' ')[1]
	#print 'New URL:',self.url
	
	new_request=1

        data = (self.client_buffer[:end+1]).split()
	print self.client_buffer
        return data

    def method_CONNECT(self):
        self._connect_target(self.path)
        self.client.send(HTTPVER+' 200 Connection established\n'+
                         'Proxy-agent: %s\n\n'%VERSION)
        self.client_buffer = ''
        self._read_write()        

    def method_others(self):
	global param_info,temp_login_info,login_url,current,state_set,transition_set,prev,global_session,login_field,login_pass_field
        self.path = self.path[7:]
        i = self.path.find('/')
        host = self.path[:i]        
        path = self.path[i:]
        self._connect_target(host)
        self.target.send('%s %s %s\n'%(self.method, path, self.protocol)+
                	       self.client_buffer)
	
	if validate(current):
		print '******************************************'
		print 'Create a state for ',current
		print 'Prev=',prev
		temp_url=''
		print 'Global Session:',global_session
		if prev!='':
			temp_url=prev.url
			if global_session!='' and global_session!=None:
				print 'Session:',global_session
				
			else:
				global_session=None
		else:
			global_session=None
			temp_url=prev
		print 'Temp url:',temp_url
		print session
		if param_info!={}:
			print 'params:',param_info
		else:
			param_info=None
		if current not in html_response:
			html_response[current]=''
		print 'Create a transition from ',prev,' to ',current
		#print 'HTML Response=',html_response[current]
		a,b=existsState(current,html_response[current])
		print a,b
		if not a:
			state_set.append(State(current,html_response[current]))
			checkAndAddTransition(prev,state_set[-1],global_session,param_info)
			prev=state_set[-1]
		else:
			checkAndAddTransition(prev,b,global_session,param_info)
			print 'State already exists'
			prev=b
		
		print '******************************************'
	param_info={}
	if self.method=='POST':
		#print 'Screw up'
		#print self.url
		#print self.client_buffer
		if ("multipart/form" not in self.client_buffer):
			param_string=self.client_buffer.split("\r\n\r\n")[1]
			param_info={}
			param={}
			param_list=param_string.split('&')
			for item in param_list:
				param[item.split('=')[0]]=item.split('=')[1]
			param_info['POST']=param
			if set(param.keys())==set([login_field,login_pass_field]):
				temp_login_info=param_string
		#print "POST request sent to URL ",self.path
		#print "Parameters:",str(param_info)
	
	
	if '?' in self.url and validate(self.url) and '=' in self.url:
		extract_url_params(self.url)
		if self.url!=logout_url and self.url!=login_url:
			self.url=self.url.split('?')[0]
	
	#print 'Setting current to ', self.url
	current=self.url
        self.client_buffer = ''
        self._read_write()

    def _connect_target(self, host):
        i = host.find(':')
        if i!=-1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 80
        #print host,port
        (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family)
        self.target.connect(address)
	

    def _read_write(self):
        #print "In readwrite ",self.url
        global ses
        global current
        global prev
        global sequence
        global session
        global stop
	global new_request
	global server
	global server_set
	global param_info
	global data_pool
	global html_response
	global logout_url,login_url,temp_login_info,global_session,num_roles,login_field,login_pass_field
        output=''
	data_pool=''
        time_out_max = self.timeout/3
        socs = [self.client, self.target]
        count = 0
        while 1:
            count += 1
            (recv, _, error) = select.select(socs, [], socs, 3)
            if error:
                break
            if recv:
                for in_ in recv:
                    data = in_.recv(BUFLEN)
                    if in_ is self.client:
                        out = self.target
                    else:
                        out = self.client
                    if data:
                        #Stub:Insert function to call extractdata() here
			if out==self.client:
				if new_request==1:
					#print 'Data pool reset'
					data_pool=''
				data_pool+=data
				new_request=0
                        	content=re.search("Content-Type:(.+?)\n",data_pool)
				if content:
					content_line=content.group(0)
					#print content_line
					if re.search("text/html",content_line):
						try:
							first_line=data_pool.split('\n')[0]
							status_code=int(first_line.split(' ')[1])
							#print "status code:",status_code
							if (int(status_code/100)==2 or (status_code<304)) and validate(self.url):
								if self.url==logout_url:
                                                			stop=True
									num_roles-=1
									if num_roles==0:
										print 'Stopping'
								#print "URL:",self.url
								if server=='':
									server_set=extract_server(data)
								if server_set:
									if '?' in self.url and validate(self.url) and '=' in self.url:
										
										extract_url_params(self.url)
										if self.url!=logout_url and self.url!=login_url:
											self.url=self.url.split('?')[0]
									
									if server=='PHP':
										#print 'PHP sesion identified'
										extract_php_session(data_pool,self.url)
									elif server=='Python':
										extract_python_session(data_pool,self.url)
									elif server=='Ruby':
										#print self.url
										#print content_line
										extract_ruby_session(data_pool,self.url)
									elif server=='JSP':
										extract_java_session(data_pool,self.url)
									#param_info={}
									
									#print 'param info cleared'
									#for i in sequence:
										#print i,' ',sequence[i]
								
						except Exception as e:
							print e
							pass
							
			if out==self.target:
				#print data
				f=open("requests.txt",'a')
				f.write(data)
				f.write('RESPONSEHEADERS\n')
				f.close()
				#print 'Requesting through readwrite'
				#print prev
				#print current
				#print data_pool
				if current!='' and '<html' in data_pool:
					print "Storing response"
					html_response[self.url]='<html'+data_pool.split('<html')[1]
				first_line = data.split('\n')[0]
				#print 'New request...'
				#print 'Current',current
				if validate(current):
					print '******************************************'
					print 'Create a state for ',current
					print 'Prev=',prev
					print 'Global Session:',global_session
					if prev!='':
						temp_url=prev.url
						if global_session!='' and global_session!=None:
							print 'Session:',global_session
				
						else:
							global_session=None
					else:
						global_session=None
						temp_url=prev
					print 'Temp url:',temp_url
					print session
					if param_info!={}:
						print 'params:',param_info
					else:
						param_info=None
					if current not in html_response:
						html_response[current]=''
					
					print 'Create a transition from ',prev,' to ',current
					#print 'HTML Response=',html_response[current]
					a,b=existsState(current,html_response[current])
					if not a:
						state_set.append(State(current,html_response[current]))
						checkAndAddTransition(prev,state_set[-1],global_session,param_info)
						prev=state_set[-1]
					else:
						checkAndAddTransition(prev,b,global_session,param_info)
						print 'BOOM',a,b
						prev=b
		
					param_info={}
					
					print '******************************************'
				if first_line.split(' ')[0]=='GET':
        				self.url = first_line.split(' ')[1]
				if first_line.split(' ')[0]=='POST':
        				self.url = first_line.split(' ')[1]
					#print "New request from ",self.url
					#print data
				
					#print data
					try:
						if ("multipart/form" not in self.client_buffer):
							param_string=data.split("\r\n\r\n")[1]
					
							param_info={}
							param={}
							
							param_list=param_string.split('&')
							for item in param_list:
								param[item.split('=')[0]]=item.split('=')[1]
							param_info['POST']=param
							if set(param.keys())==set([login_field,login_pass_field]):
								temp_login_info=param_string
					except Exception:
						pass
					#print "POST request sent to URL ",self.path
					#print "Parameters:",str(param_info)
					#param_info={}
				if '?' in self.url and validate(self.url) and '=' in self.url:
						extract_url_params(self.url)
						if self.url!=logout_url and self.url!=login_url:
							self.url=self.url.split('?')[0]
				
				#print 'Setting current to ', self.url
				current=self.url
				new_request=1	
				#print 'New URL',self.url
				
				
                        out.send(data)
			
                     
                        count = 0
            if count == time_out_max:
                break
	    if stop:
		break
        #print "Out of readwrite"

def helloworld(packet, path):
	print packet
	if '127.0.0.1' in path:
		f=open("requests.txt",'a')
		f.write(packet)
		f.write("HEADEREND\n")
		f.close()
   

def start_server(host='localhost', port=8081, IPv6=False, timeout=60,
                  handler=ConnectionHandler):
    global stop
    global session
    global sequence
    global login
    global html_response,role_id,authorized,login_url,logout_url,num_roles
    final_sequence=[]
    final_session=[]
    if IPv6==True:
        soc_type=socket.AF_INET6
    else:
        soc_type=socket.AF_INET
    soc = socket.socket(soc_type)
    soc.bind((host, port))
    print "Serving on %s:%d."%(host, port)#debug
    soc.listen(0)
    print 'Please browse like an unauthorized user first'
    while num_roles!=0:
        thread.start_new_thread(handler, soc.accept()+(timeout,))
	#print " Real Stop=",str(stop)
	stop=False
	if stop:
        	#writedata()
		if '' in sequence:
           		del sequence['']
    		#print sequence
    		for x in sequence:
			if x in sequence[x]:
				if sequence[x]==[x]:
					pass
				else:
					sequence[x].remove(x)
		final_session.append(session)
		final_sequence.append(sequence)
		session={}
		sequence={}
                time.sleep(2)
        	ch=raw_input('Press y if you have more roles to explore...,press c to change login url')
        	if ch=='y' or ch=='c':
                 	stop=False
			authorized=True
			role_id+=1
		if ch=='c':
			login_url=raw_input('Please enter the login url:')
    			logout_url=raw_input('Please enter the logout url:') 
                 	
    
    print final_session
    print final_sequence
    print params
    print login
    f=open("responses.txt",'w')
    for i in html_response:
	print i
    	f.write(i)
	f.write("\n\n")
	f.write(html_response[i])
    f.close()
    fileObject = open("db",'wb') 
    pickle.dump([state_set,transition_set,login],fileObject) 
    queue = HotQueue("myqueue", host="localhost", port=6379, db=0)
    queue.put(state_set) 
    queue.put(transition_set) 
    queue.put(login) 
    queue.put(login_url) 
    queue.put(logout_url)   
    fileObject.close()


if __name__ == '__main__':
    global login_url
    global logout_url,state_set,transition_set
    print "Start Server"
    
    #login_url=raw_input('Please enter the login url:')
    #logout_url=raw_input('Please enter the logout url:')     
    start_server()
    #print state_set
    #print transition_set
    print login
    for x in state_set:
	print 'URL:',x.url
    for x in transition_set:
	print '\n'
	if x.source!='':
		print 'Source:',x.source.url
	else:
		print 'Source:',x.source
	print 'Dest:',x.dest.url
	print 'Session:',x.session
	print 'Params:',x.params
    





