from flask import Flask,render_template,request
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField
import subprocess
from wtforms.validators import InputRequired
import mysql.connector
import os.path
import xml.dom.minidom
import datetime

now = datetime.datetime.utcnow()
app=Flask(__name__)
app.config['SECRET_KEY']='DontTellAnyone'

class LoginForm(FlaskForm):
    username = StringField()
    password =PasswordField()



mydb = mysql.connector.connect(
        host="localhost",
        user="user",
        password="",
        database="project"
)


@app.route("/" , methods=['GET','POST'])
def login():
    return render_template("login.html")

@app.route("/dash" , methods=['GET','POST'])
def dash():
    return render_template("dash.html")

@app.route("/ip/<string:user>" , methods=['GET','POST'])
def ip(user):
    return render_template("ip.html",user=user)

@app.route("/ipo/<string:user>" , methods=['GET','POST'])
def ipo(user):
    return render_template("ipo.html",user=user)

@app.route("/ipt/<string:user>" , methods=['GET','POST'])
def ipt(user):
    return render_template("ipt.html",user=user)

@app.route("/ipu/<string:user>" , methods=['GET','POST'])
def ipu(user):
    return render_template("ipu.html",user=user)

@app.route("/ipa/<string:user>" , methods=['GET','POST'])
def ipa(user):
    return render_template("ipa.html",user=user)

@app.route("/index" , methods=['GET','POST'])
def index():
    return render_template("index.html")



#for history

@app.route("/hist/<string:user>" , methods=['GET','POST'])
def hist(user):
    headings=["target ip","mac address","manufacture","scan date"]
    type="Total Network"
    mycursor =mydb.cursor()
    mycursor.execute("select targetip,mac,manufacture,dates from totalnetwork where user='"+user+"'")
    data=mycursor.fetchall()
    return render_template("his.html" ,data=data,headings=headings,type=type,user=user)


@app.route("/hist1/<string:user>" , methods=['GET','POST'])
def hist1(user):
    headings=["protocol","portno","state","service","dates"]
    type="TCP"
    mycursor = mydb.cursor()
    mycursor.execute("select protocol,portno,state,service,dates from tcp where username='"+user+"'")
    data=mycursor.fetchall()
    return render_template("his.html",data=data,headings=headings,type=type,user=user)

@app.route("/histo/<string:user>" , methods=['GET','POST'])
def histo(user):
    headings=["osname","osfamily","lastboot","boottime","date"]
    type="OS Detection"
    mycursor = mydb.cursor()
    mycursor.execute("select osname,osfamily,lastboot,boottime,dates from osdetection where user='"+user+"'")
    data=mycursor.fetchall()
    return render_template("his.html",data=data,headings=headings,type=type,user=user)

@app.route("/hista/<string:user>" , methods=['GET','POST'])
def hista(user):
    headings=["portno","service","product","version","attack method","date"]
    type="Aggressive"
    mycursor = mydb.cursor()
    mycursor.execute("select portno,service,product,version,attackmethod,dates from aggresive where user='"+user+"'")
    data=mycursor.fetchall()
    return render_template("his.html",data=data,headings=headings,type=type,user=user)

@app.route("/histu/<string:user>" , methods=['GET','POST'])
def histu(user):
    headings=["portno","service","version","hostname","date"]
    type="Version Detection"
    mycursor = mydb.cursor()
    mycursor.execute("select portno,service,version,hostname,dates from version where user='"+user+"'")
    data=mycursor.fetchall()
    return render_template("his.html",data=data,headings=headings,type=type,user=user)




@app.route('/signup', methods=['POST','GET'])
def signup():
  
    mycursor = mydb.cursor()
    if request.method =='POST':
        details = request.form
        username= details['user1']
        password = details['pass1']
        email=details['mail']
        mycursor.execute("insert into login(Uname,password) values(%s,%s)",(username,password))
        # id=mycursor.lastrowid
        mycursor.execute = ("insert into registration(Username,Email,password)values(%s,%s,%s)",(username,email,password))
        mydb.commit()
        mycursor.close()
        print(mycursor.rowcount,"record inserted")
        return '''<script> alert('Registered');window.location='/'</script>'''
    return "registration failed"
@app.route("/signin"  , methods=['POST','GET'])
def signin():
   
    mycursor = mydb.cursor()
    if request.method=='POST':
        details=request.form
        username=details['user']
        password=details['pass']
        mycursor.execute( "select *from login where Uname='"+username+"' and password='"+password+"' ")
        s=mycursor.fetchone()
        count=mycursor.rowcount
        if count==1:
            return render_template("dash.html" ,user=username)
        elif count>1:
            return "more then one user "
        else:
            return '''<script> alert('Password or Username Incorrect');window.location='/'</script>'''
   
    mydb.commit()
    mycursor.close()
@app.route('/net/<string:user>', methods=['POST','GET'])
def net(user):
    type = "Total Network Scan "
    ipstr = request.form
    print(ipstr)
    ips=ipstr['ipadd']
    file="/root/Documents/project 2.0/xmloutput/hostdiscovery.xml"
    process = subprocess.Popen(['nmap', ips,'-sn','-oX',file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    returncode = process.wait()
    my_output = process.stdout.read()
        
    my_output = my_output.decode().replace('\n', '<br>')  

        # XML CODE USING
    doc = xml.dom.minidom.parse(file);
    mycursor = mydb.cursor()

    address = doc.getElementsByTagName("address") 
    le=address.length

        #for vendor
    manufact = []
    for skill in address:
        manufact.append(str(skill.getAttribute("vendor")))

        #for ip and mac
    arr=[]
    for skill in address:
        arr.append(str(skill.getAttribute("addr")))

        # my ip address   
    

    ip=[]
    mac=[]
    man=[]
    i=0
    for i in range(le):
        if ( i%2 ==0):
            ip.append(str(arr[i]))
        else:
            mac.append(str(arr[i]))
            man.append(str(manufact[i]))

         #for inserting data into data base    
    le=le//2
    sql_drop = "DROP TABLE IF EXISTS temp"
    mycursor.execute(sql_drop)
    mycursor.execute("CREATE TABLE temp( targetip varchar(50),mac varchar(50),manufacture varchar(50));")
    mydb.commit()
    mycursor=mydb.cursor()
    for i in range(le):
        mycursor.execute("INSERT INTO totalnetwork(user,targetip,mac,manufacture,dates) VALUES (%s,%s,%s,%s,%s)",
        (user,ip[i],mac[i],man[i],now.strftime('%Y-%m-%d %H:%M:%S')))
        mycursor.execute("INSERT INTO temp(targetip,mac,manufacture) VALUES (%s,%s,%s)",
        (ip[i],mac[i],man[i]))
        mydb.commit()
    mycursor.close()
    headings=["target ip","mac address","manufacture"]
    mycursor=mydb.cursor()
    mycursor.execute("select * from temp")
    data=mycursor.fetchall()
    mydb.commit()
    mycursor.close()
    
    return render_template("/table1.html",type=type,ip=ips,data=data,headings=headings)

@app.route('/net1/<string:user>', methods=['POST','GET'])
def net1(user):
       
        type="OS Detection"
        ipstr = request.form
        print(ipstr)
        ips=ipstr['ipadd']
        file="/root/Documents/project 2.0/xmloutput/osdetection.xml"
       
        process = subprocess.Popen(['nmap', ips,'-O','-oX',file],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

        returncode = process.wait()
        my_output = process.stdout.read()
        
        my_output = my_output.decode().replace('\n', '<br>')

        doc = xml.dom.minidom.parse(file);

        #for oscmatch tag
        osmatch = doc.getElementsByTagName("osmatch") 
        la=osmatch.length
        #print("length3",la)

        #for  os name
        osname=[]
        for skill in osmatch:
            osname.append(str(skill.getAttribute("name")))
    
        #for osclass tag
        osclass = doc.getElementsByTagName("osclass") 
        la=osclass.length
         #print("length3",la)

         #for  service name
        osfam=[]
        for skill in osclass:
            osfam.append(str(skill.getAttribute("osfamily")))

        #for uptime tag
        uptime = doc.getElementsByTagName("uptime") 
        la=uptime.length
        # print("length3",la)

        #for  for lastboot
        lastboot=[]
        for skill in uptime:
            lastboot.append(str(skill.getAttribute("lastboot")))

        #for  boot duration
        time=[]
        for skill in uptime:
            time.append(str(skill.getAttribute("seconds")))


        #  for inserting data into data base
        mycursor=mydb.cursor()
        sql_drop = "DROP TABLE IF EXISTS temp"
        mycursor.execute(sql_drop)
        mycursor.execute("CREATE TABLE temp( osname varchar(50), osfamily varchar(50),lastboot varchar(50),boottime varchar(50));")
        mydb.commit()
        mycursor=mydb.cursor()
        mycursor.execute("INSERT INTO temp(osname,osfamily,lastboot,boottime) VALUES (%s,%s,%s,%s)",
        (osname[0],osfam[0],lastboot[0],time[0]))
        mycursor.execute("INSERT INTO osdetection(user,osname,osfamily,lastboot,boottime,dates) VALUES (%s,%s,%s,%s,%s,%s)",
        (user,osname[0],osfam[0],lastboot[0],time[0],now.strftime('%Y-%m-%d %H:%M:%S')))
        mydb.commit()
        mycursor.close()
    
        headings=["osname","osfamily","lastboot","boottime"]
        mycursor=mydb.cursor()
        mycursor.execute("select * from temp")
        data=mycursor.fetchall()
        mydb.commit()
        mycursor.close()
        
    
        return render_template("/table1.html",type=type,ip=ips,data=data,headings=headings)

@app.route('/net2/<string:user>', methods=['POST','GET'])
def net2(user):
       
        type="Aggresive Scan"
        ipstr = request.form
        print(ipstr)
        ips=ipstr['ipadd']
        file="/root/Documents/project 2.0/xmloutput/aggresive.xml"
        
        process = subprocess.Popen(['nmap', ips,'-A','-oX',file],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        returncode = process.wait()
        my_output = process.stdout.read()
        
        my_output = my_output.decode().replace('\n', '<br>')

        doc = xml.dom.minidom.parse(file);
        mycursor = mydb.cursor()
        
        
        # get a list of XML tags from the document and print each one
        port = doc.getElementsByTagName("port") 
        le=port.length
    

        #for portid
        portid=[]
        for skill in port:
            portid.append(str(skill.getAttribute("portid")))
    
        #for service tag
        service = doc.getElementsByTagName("service") 
        le=service.length
        

        #for  service name
        name=[]
        for skill in service:
            name.append(str(skill.getAttribute("name")))

        product=[]
        for skill in service:
            product.append(str(skill.getAttribute("product")))

        version=[]
        for skill in service:
            version.append(str(skill.getAttribute("version")))

    
        #for script tag
        atkmethod = doc.getElementsByTagName("script") 
        la=atkmethod.length
       

        atk=[]
        for skill in atkmethod:
            atk.append(str(skill.getAttribute("id")))


        #  for inserting data into data base
    
        sql_drop = "DROP TABLE IF EXISTS temp"
        mycursor.execute(sql_drop)
        mycursor.execute("CREATE TABLE temp( portno varchar(50), service varchar(50),product varchar(50),version varchar(50), attackmethod varchar(50));")
        mydb.commit()
        i=0
        for i in range(le):
            mycursor.execute("INSERT INTO aggresive(user,portno,service,product,version,attackmethod,dates) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (user,portid[i],name[i],product[i],version[i],atk[i],now.strftime('%Y-%m-%d %H:%M:%S')))
            mycursor.execute("INSERT INTO temp(portno,service,product,version,attackmethod) VALUES (%s,%s,%s,%s,%s)",
            (portid[i],name[i],product[i],version[i],atk[i]))
            mydb.commit()
        
              # print(mycursor.rowcount,"record inserted")
        mycursor.close()

        headings=["portno","service","product","version","attack method"]
        mycursor=mydb.cursor()
        mycursor.execute("select * from temp")
        data=mycursor.fetchall()
        mydb.commit()
        mycursor.close()
        
        return render_template("/table1.html",type=type,ip=ips,data=data,headings=headings)

@app.route('/net3/<string:user>', methods=['POST','GET'])
def net3(user):
       
        type="TCP SYK  Scan"
        ipstr = request.form
        print(ipstr)
        ip=ipstr['ipadd']
        file="/root/Documents/project 2.0/xmloutput/tcp.xml"
        

        process = subprocess.Popen(['nmap', ip,'-PS','-oX',file],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        returncode = process.wait()
        my_output = process.stdout.read()
        
        my_output = my_output.decode().replace('\n', '<br>')

        doc = xml.dom.minidom.parse(file);
        mycursor = mydb.cursor()

        ips=ip
        
        # get a list of XML tags from the document and print each one
        port = doc.getElementsByTagName("port") 
        le=port.length
   
        #for protocol
        Protocol = []
        for skill in port:
            Protocol.append(str(skill.getAttribute("protocol")))
        

        #for portid
        portid=[]
        for skill in port:
            portid.append(str(skill.getAttribute("portid")))
    
        #for state tag
        state = doc.getElementsByTagName("state") 
        le=state.length
    

        #for state
        states=[]
        for skill in state:
            states.append(str(skill.getAttribute("state")))
    

        #for service tag
        service = doc.getElementsByTagName("service") 
        le=service.length

        #for  service name
        name=[]
        for skill in service:
            name.append(str(skill.getAttribute("name")))
    
   
        #  for inserting data into data base
        sql_drop = "DROP TABLE IF EXISTS temp"
        mycursor.execute(sql_drop)
        mycursor.execute("CREATE TABLE temp( protocol varchar(50), portno varchar(50),state varchar(50),service varchar(50));")
        mydb.commit()
        i=0
        for i in range(le):
            mycursor.execute("INSERT INTO tcp(username,protocol,portno,state,service,dates) VALUES (%s,%s,%s,%s,%s,%s)",
            (user,Protocol[i],portid[i],states[i],name[i],now.strftime('%Y-%m-%d %H:%M:%S')))
            mycursor.execute("INSERT INTO temp(protocol,portno,state,service) VALUES (%s,%s,%s,%s)",
            (Protocol[i],portid[i],states[i],name[i]))
            mydb.commit()
        
       
        mycursor.close()

        headings=["protocol","portno","state","service"]
        mycursor=mydb.cursor()
        mycursor.execute("select * from temp")
        data=mycursor.fetchall()
        mydb.commit()
        mycursor.close()
        
        return render_template("/table1.html",type=type,ip=ips,data=data,headings=headings)

@app.route('/net4/<string:user>', methods=['POST','GET'])
def net4(user):
       
        type="Version Detection"
        ipstr = request.form
        print(ipstr)
        ip=ipstr['ipadd']
        file="/root/Documents/project 2.0/xmloutput/version.xml"
        process = subprocess.Popen(['nmap', ip,'-sV','-oX',file],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        returncode = process.wait()
        my_output = process.stdout.read()
        
        my_output = my_output.decode().replace('\n', '<br>') 

        doc = xml.dom.minidom.parse(file);
        mycursor = mydb.cursor()

        ips=ip
         
        # get a list of XML tags from the document and print each one
        port = doc.getElementsByTagName("port") 
        le=port.length
       

        #for portid
        portid=[]
        for skill in port:
            portid.append(str(skill.getAttribute("portid")))
    
   
    

        #for service tag
        service = doc.getElementsByTagName("service") 
        le=service.length
    
        #for  service name
        name=[]
        for skill in service:
            name.append(str(skill.getAttribute("name")))

        version=[]
        for skill in service:
            version.append(str(skill.getAttribute("version")))

        hostname=[]
        for skill in service:
            hostname.append(str(skill.getAttribute("hostname")))

        #  for inserting data into data base
        sql_drop = "DROP TABLE IF EXISTS temp"
        mycursor.execute(sql_drop)
        mycursor.execute("CREATE TABLE temp( portno varchar(50), service varchar(50),version varchar(50),hostname varchar(50));")
        mydb.commit()
        i=0
        for i in range(le):
            mycursor.execute("INSERT INTO version(user,portno,service,version,hostname,dates) VALUES (%s,%s,%s,%s,%s,%s)",
            (user,portid[i],name[i],version[i],hostname[i],now.strftime('%Y-%m-%d %H:%M:%S')))
            mycursor.execute("INSERT INTO temp(portno,service,version,hostname) VALUES (%s,%s,%s,%s)",
            (portid[i],name[i],version[i],hostname[i]))
            mydb.commit()
    
        
        mycursor.close()
    
        headings=["portno","service","version","hostname"]
        mycursor=mydb.cursor()
        mycursor.execute("select * from temp")
        data=mycursor.fetchall()
        mydb.commit()
        mycursor.close()
        
        
        return render_template("/table1.html",type=type,ip=ips,data=data,headings=headings)

if __name__=="__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
