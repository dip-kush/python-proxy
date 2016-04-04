class State:
	def __init__(self,url,dom):
		self.url=url
		self.dom=dom

class transition:
	def __init__(self,source,dest,session,params):
		self.source=source
		self.dest=dest
		self.session=session
		self.params=params
	def addSession(self,sess):
		if sess==None:
			pass
		elif self.session==None:
			self.session=[sess]
		else:
			self.session.extend(sess)

class role:
	def __init__(self,role_id,login_info,session):
		self.role_id=role_id
		self.login_info=login_info
		self.session=session

class vulnerability:
	def __init__(self,vul_type,url,role_info,params,param_info):
		self.vul_type=vul_type
		self.url=url
		self.params=params
		self.role_info=role_info
		self.param_info=param_info

	def describe(self):
		print '\n\nVulnerability of type ',str(self.vul_type)
		print 'URL:',self.url
		if self.params!=None:
			print 'POST params:',str(self.params)
		if self.role_info=='All':
			print 'Role:Unauthenticated'
		elif self.role_info!=None:
			print 'Role:',str(self.role_info)
		if self.param_info!=None:
			print 'It is expected that the value of ',str(self.param_info[0]), 'and ',str(self.param_info[1]),' are to be same, but the check is not made'
