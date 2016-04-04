import lxml
from lxml import etree
from bs4 import BeautifulSoup
from Queue import *

#This function returns 1 if no vulnerability is found ie dom is different
#Otherwise it returns 0 ie dom is same and vulnerability is found

def html_compare(document1,document2):
		parser = etree.HTMLParser()
		dom1=etree.fromstring(document1, parser)
		dom2=etree.fromstring(document2, parser)
		root1=dom1
		root2=dom2
		flg=0
		q1=Queue()
		q2=Queue()
		if(root1.tag==root2.tag):
			q1.put(root1)
			q2.put(root2)
		else:
			flg=1
		while(q1.empty()==False and q2.empty()==False):
			b1=q1.get()
			b2=q2.get()
			l1=len(b1.getchildren())
			l2=len(b2.getchildren())
			#print b1.getchildren(),b2.getchildren()
			if (b1.tag!='ol' and b2.tag!='ol')and (b1.tag!='table' and b2.tag!='table') and (b1.tag!='ul' and b2.tag!='ul'):
				#print "Look here", b1.tag,b2.tag
				if(l1!=l2):
					flg=1
					print 'Unequal children'
					#print b1.tag,b2.tag
					#print b1.getchildren(),b2.getchildren()
					print l1,l2
					#print document1
					#print document2
					#ch=raw_input("Press any key")
					break
				else:
					i=0
					while(i<l1):
						#print 'while'
						x=b1.getchildren()[i]
						y=b2.getchildren()[i]
						#print x,y
						#print x.getchildren(),y.getchildren()
						#print 'Tails',(x.tail)
						#print 'Tails',(y.tail)
						#print x.tail==' '
						#print x.tail=='\r\n'
						#print 'Strip',repr(y.tail.strip())
						if (x.tail==None or y.tail==None) or(x.tail=='\n ' and y.tail=='\n ') or (not x.tail and not y.tail) or (x.tail.strip()=='' and y.tail.strip()==''):
							#print 'No tails'
							#print 'Tags',x.tag,y.tag
							if x.tag!=y.tag:
								#print 'Tags dont match'
								flg=1
								#print x.tag,y.tag
								break
							else:
								q1.put(x)
								q2.put(y)
								#print 'Queing'
						elif x.tail and y.tail:
							if x.tail!=y.tail:
								flg=1
								#print x.tail,y.tail
								break
						else:
							flg=1
							#print x,y
							#print x.tail,y.tail
							#print x.tag,y.tag
							print 'Unknown'
							#print document1
							#print document2
							#ch=raw_input("Press any key")
							break
						i=i+1
					if flg==1:
						break
		if flg==1:

			print("COMPARISON FINISHED\nNo vuln\n\n ")
			return False
		else:

			print("COMPARISON FINISHED\nvuln Found !!!\n\n ")
			return True


benign1="""<html><head><title>Title1</title></head><body><b>Hi</b></body></html>"""
benign2="<html><head><title>Title2</title></head><body><b>Hi</b></body></html>"
hostile1="<html><head><title>Title3</title></head><body><b>Hi</b><b>Boom</b></body></html>"
#html_compare(benign1,benign1)

