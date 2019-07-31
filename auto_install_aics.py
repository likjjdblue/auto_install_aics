#!/usr/bin/env python
#-*- coding: utf-8 -*-


import subprocess
from time import sleep
from os import geteuid,path,makedirs,rename,environ
from sys import exit
import re
from resource import setrlimit,getrlimit,RLIMIT_NOFILE
import httplib
import json
import socket
import sys
from collections import defaultdict
from commands import getoutput
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from ESScript  import ESScript
import hashlib

EnableLocalYum=False   ####是否开启本地YUM源开关，如果开启就跳过对Internet的检测  2018-02-26 新增   ####

TextColorRed='\x1b[31m'
TextColorGreen='\x1b[32m'
TextColorWhite='\x1b[0m'

validAppNameList=['java','opencv','python3',
                 'elasticsearch','logstash','nginx',
                 'clickhouse','neo4j','mariadb']


CPUCores='1' if getoutput("lscpu|grep '^CPU(s)'|awk '{print $2}'")=='1' else getoutput("lscpu|grep '^CPU(s)'|awk '{print $2}'")

AppInstalledState={}   ###已经成功安装的软件名称会存放在这里###

WikiURL='http://t.cn/REQVj8w'         #### WIKI 部署文档短地址   ##

def checkRootPrivilege():
###  检查脚本的当前运行用户是否是 ROOT ###
  RootUID=subprocess.Popen(['id','-u','root'],stdout=subprocess.PIPE).communicate()[0]
  RootUID=RootUID.strip()
  CurrentUID=geteuid()
  return str(RootUID)==str(CurrentUID)

def extractLocalIP():
    return subprocess.Popen("ip addr|grep 'state UP' -A2|tail -n1|awk '{print $2}'|cut -f 1 -d '/'",
                            shell=True,stdout=subprocess.PIPE).communicate()[0].strip()

def checkPortState(host='127.0.0.1',port=9200):
### 检查对应服务器上面的port 是否处于TCP监听状态 ##

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    try:
       s.connect((host,port))
       return {'RetCode':0,
               'Result':TextColorGreen+str(host)+':'+str(port)+'处于监听状态'+TextColorWhite}
    except:
       return {'RetCode':1,
               'Result':TextColorRed+'无法访问'+str(host)+':'+str(port)+TextColorWhite}

def checkCompilerState():
#### 检查C,C++ 编译器状态   ###
    errorA=subprocess.Popen(['which','c++'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
    errorB=subprocess.Popen(['which','gcc'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]

    if errorA or errorB:
       print (TextColorRed+'GCC或者C++编译器尚未安装，即将联网进行安装....'+TextColorWhite)
       InternetState=checkInternetConnection()
       if InternetState['RetCode']!=0:
          print (TextColorRed+InternetState['Description']+' 程序退出!'+TextColorWhite)
          exit(1)
       print (TextColorGreen+InternetState['Description']+TextColorWhite)
       if subprocess.call('yum install -y gcc gcc-c++',shell=True):
           print (TextColorRed+'联网安装GCC,C++ 编译器失败！程序退出!')
           exit(1)
    print (TextColorGreen+'GCC,C++ 编译器已经安装成功!'+TextColorWhite)
         
def __checkOSVersion():
#### 检查操作系统的版本，确保是Centos 7 的版本 ###
    OSInfoFileList=['/etc/centos-release']
    for filepath in OSInfoFileList:
      if path.isfile(filepath):
         TmpFileObj=open(filepath,mode='r')
         FileContent=TmpFileObj.read()
         FileContent=FileContent.strip()
         TmpFileObj.close()
         ReObj=re.search(r'\s+([\d\.]+)\s+',FileContent)
         if ReObj and ('CentOS' in FileContent):
            OSVersion=ReObj.group(1)
            if re.search(r'^7.*',OSVersion):
               print (TextColorGreen+'操作系统满足要求!'+TextColorWhite)
               return 0
            else:
               print (TextColorRed+'操作系统不满足要求(需要CentOS7)，当前系统:'+str(FileContent)+'\n程序退出!'+TextColorWhite)
               exit(1)
    print (TextColorRed+'无法获取操作系统版本信息，或者版本不符合要求(需要CentOS7)'+'\n程序退出!'+TextColorWhite)
    exit(1)
    
def __installMysqlDriver4Python():
    try:
        import mysql.connector
    except:
        subprocess.call('rpm -Uvh --force install_package/mysql-connector-python-2.1.7-1.el7.x86_64.rpm',
                        shell=True)
        import mysql.connector

def __installPexpect():
    try:
        import pexpect
    except:
        subprocess.call('rpm -Uvh install_package/pexpect/*.rpm',
                        shell=True)
        subprocess.call('/usr/bin/pip install install_package/pexpect/ptyprocess-0.6.0.tar.gz',
                        shell=True)
        subprocess.call('/usr/bin/pip install install_package/pexpect/pexpect-4.7.0.tar.gz',
                        shell=True)

          

def configureServerArgument():
#### 修改/etc/security/limits.conf 将max open-file-descriptors 修改成65535
#### 由于不确定业务账号与平台的关联性，因此可能存在部分账号nofile 参数值
#### 被调大的可能性。

    if not  checkRootPrivilege():
       print (TextColorRed+"安装失败：安装过程需要使用root账号，请切换至root账号，然后重试!"+TextColorWhite)
       exit(1)

    #### 修改前先备份原始文件 ####
    if not path.isfile(r'/etc/security/limits.conf.backup'):
        subprocess.call(['cp','/etc/security/limits.conf','/etc/security/limits.conf.backup'])
 
    ReObj=re.compile(r'^\s*[^#]*nofile\s*(?P<value>\d*)\s*$')
    InputFile=open(r'/etc/security/limits.conf',mode='r')

    FileContent=''
    for line in InputFile:       ###逐行读取limits.conf，如果当前行配置了nofile且值低于65535,那么值将被修改成65535
       RetObj=ReObj.search(line)
       if RetObj and int(RetObj.group('value'))<65535:
           line=re.sub(r'(^\s*[^#]*nofile\s*)(?P<value>\d*)\s*$',r'\1 65535',line) 
           FileContent+=line+'\n'
           continue
       FileContent+=line
    InputFile.close()

    Matched=re.search(r'#+.*?Codes below.*?#+',FileContent)
    if not Matched:
       FileContent+='#### Codes below are manually added #####\n'
       FileContent+='*     -    nofile    65535\n'

    OutputFile=open(r'/etc/security/limits.conf',mode='w')
    OutputFile.write(FileContent)
    OutputFile.close()
   
    ### 在当前脚本环境中将nofile设置成65535 ###                                            
    setrlimit(RLIMIT_NOFILE,(65535,65535))
           

def installJava():
    try:
       JavaVersionString=subprocess.Popen(['/TRS/APP/jdk1.8/bin/java','-version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
    except Exception as e:
       JavaVersionString=str(e)
    ReObj=re.search(r'java version\s+(.*?)\n',JavaVersionString)

    if ReObj and ReObj.group(1).strip('"').startswith('1.8'):
       print (TextColorGreen+'JAVA 版本满足要求(需要JAVA版本8):'+str(ReObj.group(1).strip('"'))+TextColorWhite)
       AppInstalledState['java']='ok'
    else:
       print (TextColorRed+'JAVA版本不满足要求（需要JAVA版本8)！'+TextColorWhite)
       print ('即将安装JAVA 8,请耐心等待........')

       try:
          makedirs('/TRS/APP')
          print (TextColorGreen+'/TRS/APP/目录创建成功!'+TextColorWhite)
       except:
          if not path.isdir('/TRS/APP'):
             print (TextColorRed+'无法创建/TRS/APP/目录，程序退出!'+TextColorWhite)
             AppInstalledState['java']='not ok'
             exit(1)   

          print (TextColorGreen+'/TRS/APP目录已经存在，无需新建!'+TextColorWhite)
       finally:
          pass

       result,error=subprocess.Popen(['tar','-C','/TRS/APP/','-xvzf','install_package/jdk-8u111-linux-x64.tar.gz'],\
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
          
          
       if len(error)>0:
          print (TextColorRed+error+TextColorWhite)
          print (TextColorRed+'错误：无法解压JAVA安装包,程序退出!'+TextColorWhite)
          AppInstalledState['java']='not ok'
          exit(1)
       print (TextColorGreen+'JAVA8压缩包解压完成!'+TextColorWhite)
       try:
          rename(r'/TRS/APP/jdk1.8.0_111','/TRS/APP/jdk1.8')
          print (TextColorGreen+'文件夹已经重命名为jdk1.8'+TextColorWhite)
       except:
          print (TextColorRed+'/TRS/APP目录下包含有一个名为jdk1.8 的文件或目录，重命名操作失败。')
          print(TextColorRed+'请删除或备份该目录（文件夹），并重新运行该脚本!\n'+'安装失败，程序退出!'+TextColorWhite)
          AppInstalledState['java']='not ok'
          exit(1)
          

    #### 配置JAVA 环境变量####
    print ('正在配置JAVA 环境变量，请稍等..........')
    JavaEnvironDict={'JAVA_HOME':'/TRS/APP/jdk1.8',\
            'PATH':'$JAVA_HOME/bin:$PATH',\
            'CLASSPATH':'.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar',
            'JRE_HOME':'/TRS/APP/jdk1.8/jre',
            }
    tmpDict={'JAVA_HOME':environ.get('JAVA_HOME'),\
             'PATH':environ.get('PATH'),
             'CLASSPATH':environ.get('CLASSPATH'),
             'JRE_HOME':environ.get('JRE_HOME')
            }
    
    if tmpDict['JAVA_HOME']!=JavaEnvironDict['JAVA_HOME'] or tmpDict['CLASSPATH']!=JavaEnvironDict['CLASSPATH']:
       environ['JAVA_HOME']=JavaEnvironDict['JAVA_HOME']
       environ['CLASSPATH']=JavaEnvironDict['CLASSPATH']
       environ['PATH']=JavaEnvironDict['JAVA_HOME']+'/bin:'+tmpDict['PATH']
       environ['JRE_HOME']=JavaEnvironDict['JAVA_HOME']+'/jre' 

### 检查/etc/profile中是否永久配置了JAVA 环境变量###
    InputFile=open(r'/etc/profile','r')
    FileContent=InputFile.read()
    InputFile.close()

    ReObjA=re.search(r'^\s*export\s*JAVA_HOME=/TRS/APP/jdk1\.8\n',FileContent,flags=re.MULTILINE) ## 检查JAVA_HOME ###
    ReObjB=re.search(r'^\s*export\s*CLASSPATH=\.:\$JAVA_HOME/lib/dt\.jar:\$JAVA_HOME/lib/tools\.jar\s*\n',FileContent,flags=re.MULTILINE) ## 检查CLASSPATH ##
    ReObjC=re.search(r'^\s*export\s*JRE_HOME=/TRS/APP/jdk1\.8/jre/?\n',FileContent,flags=re.MULTILINE) ###检查JRE_HOME ###
        
    if (not ReObjA) or (not ReObjB) or (not ReObjC):
       if not path.isfile(r'/etc/profile.backup'):   ###修改前备份/etc/profile ###
          subprocess.call(['cp','/etc/profile','/etc/profile.backup'])

       OutputFile=open(r'/etc/profile',mode='a')
       OutputFile.write('\n')
       OutputFile.write('export  JAVA_HOME='+JavaEnvironDict['JAVA_HOME']+'\n')
       OutputFile.write('export  PATH='+JavaEnvironDict['PATH']+'\n')
       OutputFile.write('export  CLASSPATH='+JavaEnvironDict['CLASSPATH']+'\n')
       OutputFile.write('export  JRE_HOME='+JavaEnvironDict['JRE_HOME']+'\n')
       OutputFile.close()
    AppInstalledState['java']='ok'
    print (TextColorGreen+'JAVA 环境变量配置完毕!'+TextColorWhite)


       

def checkInternetConnection():
    global EnableLocalYum
    if EnableLocalYum:
        print ('当前开启了本地YUM源，跳过对互联网的检测.')
        return {'RetCode':0,
                'Description':'当前开启了本地YUM源，跳过对Internet的检测'}
    pingResult,pingError=subprocess.Popen(['ping','61.139.2.69','-c 2','-W 1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    ReObj=re.search(r'(\d+)\s+received',pingResult)
    PacketRecived=int(ReObj.group(1))
 
    DNSResult,DNSError=subprocess.Popen(['ping','www.baidu.com','-c 1','-W 1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

    if PacketRecived>0 and DNSResult:
        return {'RetCode':0,
                 'Description':'网络畅通，DNS解析正常'}
    elif PacketRecived>0 and DNSError:
        return {'RetCode':1,
                 'Description':'网络畅通，DNS解析异常，请检查DNS服务器设置'}
    else:
        return {'RetCode':2,
                'Description':'无法连接互联网'}
    
    




def sendHttpRequest(host='127.0.0.1',port=9200,url='/',method='GET',body={},header={}):
#### 调用特定的 web API,并获取结果 ###
### 函数返回Dict 类型，其中'RetCode'，标识是否异常 0:正常，非0：异常
### 'Result'是具体结果 
    
     try:
        if (not isinstance(body,dict)) or (not isinstance(header,dict)):
            raise Exception(TextColorRed+"需要传入Dict类型，参数调用异常！"+TextColorWhite)

        tmpBody=json.dumps(body)
        HttpObj=httplib.HTTPConnection(host,port)
        HttpObj.request(url=url,method=method,body=tmpBody,headers=header)
        response=json.loads(HttpObj.getresponse().read())
        return {'RetCode':0,
                 'Result':response}
     except Exception as e:
       return {'RetCode':1,
               'Result':TextColorRed+str(e)+TextColorWhite}
        
        


    
def installElasticsearch():
    LocalIPAddr=extractLocalIP()
    if subprocess.call('id -u es',shell=True):  ###首先检查es 账号是否存在###
       print ('ES 账户不存在，需新建。')
       subprocess.call('useradd es',shell=True)
       print (TextColorGreen+'新建ES 账号完成'+TextColorWhite)
       subprocess.call('passwd -l es',shell=True) ####对于通过脚本新建的 es 账号，默认是锁定的(避免弱口令)；其他方式的不受影响###
    else:
       print (TextColorGreen+"ES 账号已经存在。"+TextColorWhite)

    if not path.isdir(r'/TRS/APP'):
       subprocess.call('mkdir -p /TRS/APP/',shell=True)

    if path.exists(r'/TRS/APP/elasticsearch-6.4.3'):
       print (TextColorRed+'检测到/TRS/APP 目录下已经存在一个名为"elasticsearch-6.4.3"的文件或目录，')
       print (TextColorRed+'请删除或对其进行重命名，并重新运行该工具。')
       print (TextColorRed+'Elasticsearch 安装失败，程序退出!'+TextColorWhite)
       AppInstalledState['elasticsearch']='not ok'
       exit(1)

    subprocess.call('tar -C /TRS/APP -xvzf install_package/elasticsearch-6.4.3.tar.gz',shell=True)
    print (TextColorGreen+'Elasticsearch压缩包解压完毕。')

    subprocess.call("sed -i 's/#network\.host: 192\.168\.0\.1/network\.host: 0\.0\.0\.0/g' /TRS/APP/elasticsearch-6.4.3/config/elasticsearch.yml",
                    shell=True)
    
    print (TextColorGreen+'Elasticsearch解压完毕。'+TextColorWhite)

#### 修改操作系统参数 ###

    FileObj=open(r'/etc/security/limits.conf',mode='rb')  ####永久修改 nofile  ###
    FileContent=FileObj.read()
    FileObj.close()

    ReObjA=re.search(r'^\s*es\s+hard\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    ReObjB=re.search(r'^\s*es\s+soft\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    ReObjC=re.search(r'^\s*es\s+-\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    
    if ((not ReObjA) or (not ReObjB)) and (not ReObjC):
       if not path.isfile(r'/etc/security/limits.conf.backup'):  ### 修改前先备份  ##
          subprocess.call('cp /etc/security/limits.conf /etc/security/limits.conf.backup',shell=True)
       subprocess.call("echo 'es - nofile 65536' >>/etc/security/limits.conf",shell=True)


####   检查 /etc/sysctl.conf 中vm.max_map_count  的配置情况 ###
    if not path.isfile(r'/etc/sysctl.conf.backup'):
       subprocess.call('cp /etc/sysctl.conf /etc/sysctl.conf.backup',shell=True)

    FileObj=open(r'/etc/sysctl.conf',mode='rb')
    FileContent=FileObj.read()
    FileObj.close()

    tmpList=list(int(x) for x in re.findall(r'^\s*vm.max_map_count\s*=\s*(\d*)\s*$',FileContent,flags=re.MULTILINE))

    if len(tmpList)==0:   ###没有在 /etc/sysctl.conf  中配置vm.max_map_count ###
       subprocess.call("echo 'vm.max_map_count = 655360' >>/etc/sysctl.conf",shell=True)
    elif (len(tmpList)>=1 and max(tmpList)<655360) or (tmpList[-1]<655360):   #### 修正/etc/sysctl.conf 中不不符合要求的vm.max_map_count 参数
       ###首先，删除垃圾数据;然后重新写入###
       FileContent=re.sub(r'^\s*vm.max_map_count\s*=\s*(\d*)\s*$',r'',FileContent,flags=re.MULTILINE)  
       FileObj=open(r'/etc/sysctl.conf',mode='wb')
       FileObj.write(FileContent)
       FileObj.write('vm.max_map_count = 655360'+'\n')
       FileObj.close()


    subprocess.call("chown -R es:es /TRS/APP/elasticsearch-6.4.3",shell=True)

    print (TextColorGreen+'Elasticsearch 系统参数配置完毕.'+TextColorWhite)

####   添加ik分词器插件  ####
    subprocess.call('tar -C /TRS/APP/elasticsearch-6.4.3/plugins  -xvzf install_package/ik.tar.gz',shell=True)
    subprocess.call("chown -R es:es /TRS/APP/elasticsearch-6.4.3",shell=True)
    print (TextColorGreen+'elasticsearch分词器安装完毕!'+TextColorWhite)

#### 添加 analysis-hanlp 分词器 ###
    subprocess.call('mkdir -p /TRS/APP/elasticsearch-6.4.3/plugins/analysis-hanlp',shell=True)
    subprocess.call('mkdir -p /TRS/APP/elasticsearch-6.4.3/config/analysis-hanlp',shell=True)
    subprocess.call('tar -C /TRS/APP/elasticsearch-6.4.3/plugins  -xvzf install_package/analysis-hanlp.tar.gz',shell=True)
    subprocess.call('cp -r /TRS/APP/elasticsearch-6.4.3/plugins/analysis-hanlp/config/*  /TRS/APP/elasticsearch-6.4.3/config/analysis-hanlp',shell=True)
    subprocess.call("chown -R es:es /TRS/APP/elasticsearch-6.4.3",shell=True)


####   配置分词器 ####
    print ('正在配置elasticsearch分词器，请稍候......')
    subprocess.call('sysctl vm.max_map_count=655360;su - es -c /TRS/APP/elasticsearch-6.4.3/bin/elasticsearch &',shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    print ('正在尝试启动elasticsearch，请稍候......')
    isElasticRunning=False

    for icount in range(7):
         print ('尝试次数:'+str(icount+1))
         sleep(7)
         is9200Listening=checkPortState('127.0.0.1',9200)['RetCode']
         if is9200Listening==0:
            print (TextColorGreen+'Elasticsearch 正在监听9200端口。'+TextColorWhite)
            isElasticRunning=True
            break
         else:
             sleep(5)

    if not isElasticRunning:
         print (TextColorRed+'无法启动Elasticsearch'+TextColorWhite)
         print (TextColorRed+'配置elasticsearch 分词器失败，程序退出!'+TextColorWhite)
         AppInstalledState['elasticsearch']='not ok'
         exit(1)

    ### 创建 index ####
    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/_analyze',method='PUT',header={'Content-Type':'application/json'})

    ### 设置默认分词器## 

    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/aics_log',
                   method='PUT',header={'Content-Type':'application/json'},body=ESScript.DictA)


    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/fulltext',
                   method='PUT',header={'Content-Type':'application/json'},body=ESScript.DictB)
    print (TextColorGreen+'分词器设置完毕。'+TextColorWhite)
    print (TextColorGreen+'Elasticsearch  已经成功安装并配置。'+TextColorWhite)
    AppInstalledState['elasticsearch']='ok'


def installLogstash():
   if path.exists(r'/TRS/APP/logstash-6.4.3'):
      print (TextColorRed+'/TRS/APP 目录下已经存在一个名为logstash-6.4.3的文件或目录，请对其删除或重命名备份，'+TextColorWhite)
      print (TextColorRed+'然后重新运行本工具。'+TextColorWhite)
      print (TextColorRed+'logstash安装失败！\n 程序退出。'+TextColorWhite)
      AppInstalledState['logstash']='not ok'
      exit(1)
   
   if not path.isdir(r'/TRS/APP'):
     subprocess.call('mkdir -p /TRS/APP',shell=True)

   print ('即将解压Logstash,请稍候......')
   subprocess.call('tar -C /TRS/APP -xvzf install_package/logstash/logstash-6.4.3.tar.gz',shell=True)
   print (TextColorGreen+'Logstash解压完毕。'+TextColorWhite)
   AppInstalledState['logstash']='ok'


def installNginx():
   print (TextColorWhite+'即将编译安装NGINX,请稍候....'+TextColorWhite)
   checkCompilerState()
   subprocess.call('cd  install_package/source_nginx;tar -xvzf nginx-1.13.9.tar.gz',shell=True)
   subprocess.call('cd  install_package/source_nginx;tar -xvzf openssl-1.0.2n.tar.gz',shell=True)
   subprocess.call('cd  install_package/source_nginx;tar -xvzf pcre-8.41.tar.gz',shell=True)
   subprocess.call('cd  install_package/source_nginx;tar -xvzf zlib-1.2.11.tar.gz',shell=True)

   cmdline='cd install_package/source_nginx/nginx-1.13.9;./configure  --with-pcre=../pcre-8.41 --with-zlib=../zlib-1.2.11 \
             --with-openssl=../openssl-1.0.2n --with-stream --with-mail=dynamic \
             --prefix=/TRS/APP/nginx'

   if subprocess.call(cmdline,shell=True):
      print (TextColorRed+'Nginx configure 失败,程序退出。'+TextColorWhite)
      AppInstalledState['nginx']='not ok'
      exit(1)
   print (TextColorGreen+'Nginx configure 成功'+TextColorWhite)

   if subprocess.call('cd install_package/source_nginx/nginx-1.13.9;make -j %s'%(CPUCores,),shell=True):
      print (TextColorRed+'Nginx make 失败，程序退出。'+TextColorWhite)
      AppInstalledState['nginx']='not ok'
      exit(1)

   if subprocess.call('cd install_package/source_nginx/nginx-1.13.9;make install',shell=True):
      print (TextColorRed+'Nginx 安装 失败，程序退出。'+TextColorWhite)
      AppInstalledState['nginx']='not ok'
      exit(1)

   print (TextColorGreen+'Nginx 安装成功'+TextColorWhite)
   AppInstalledState['nginx']='ok'

#####   配置    NGINX 待续  ###
   if not path.exists(r'/etc/profile.backup'):
      subprocess.call('cp /etc/profile /etc/profile.backup',shell=True)

   FileContent=open(r'/etc/profile',mode='rb').read()
   if not re.search(r'^[^#]*/TRS/APP/nginx/sbin/?',FileContent,flags=re.MULTILINE):
      subprocess.call("echo 'export  PATH=/TRS/APP/nginx/sbin:${PATH}' >>/etc/profile",shell=True)

   

   
def installRedis():
    print (TextColorWhite+'即将安装Redis,请稍候...'+TextColorWhite)
    InternetState=checkInternetConnection()   
    if InternetState['RetCode']!=0:
       print (TextColorRed+InternetState['Description']+TextColorWhite)
       print (TextColorRed+'Redis安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)
    print (TextColorGreen+'网络检测畅通,安装继续。'+TextColorWhite)
    if  subprocess.call('yum install -y tcl gcc gcc-c++',shell=True):
       print (TextColorRed+'联网安装tcl失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)
    if subprocess.call('cd install_package/;tar -xvzf redis-stable.tar.gz',shell=True):
       print (TextColorRed+'解压Redis压缩包失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)

    if subprocess.call('cd install_package/redis-stable;make -j %s'%(CPUCores,),shell=True):
       print (TextColorRed+'Redis 安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)

    if subprocess.call('cd install_package/redis-stable;make install',shell=True):
       print (TextColorRed+'Redis 安装失败，程序退出.'+TextColorGreen)
       AppInstalledState['redis']='not ok'
       exit(1)
#    print (TextColorGreen+'Redis 安装成功.'+TextColorWhite)
    AppInstalledState['redis']='ok'


    ####### 配置 redis #####
    with open(r'install_package/redis_conf/redis',mode='r') as f:
       TmpFileContent=f.read()

    with open(r'/etc/init.d/redis',mode='w') as f:
       f.write(TmpFileContent)

    subprocess.call('chmod 777 /etc/init.d/redis;systemctl daemon-reload',shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with open(r'install_package/redis_conf/redis.conf',mode='r') as f:
        TmpFileContent=f.read()

    TmpRedisPasswd=raw_input('请输入Redis密码，并按回车(直接回车将使用默认密码:trs@admin)：')
    TmpRedisPasswd=TmpRedisPasswd.strip()
    if len(TmpRedisPasswd)==0:
       print (TextColorGreen+'未输入任何密码，使用默认密码'+TextColorWhite)
    else:
       TmpFileContent=re.sub(r'^(\s*requirepass)(.*?)\n',r'\g<1>  '+TmpRedisPasswd+'\n\n',TmpFileContent,flags=re.MULTILINE)

    with open(r'/etc/redis.conf',mode='w') as f:
       f.write(TmpFileContent)

    print (TextColorGreen+'Redis 安装成功.'+TextColorWhite)
       



def installRabbitmq():
   print (TextColorWhite+'安装Rabbitmq，请稍候...'+TextColorWhite)

   ### 新增 对openssl的安装  Added at 2018-03-06 ###
   InternetState=checkInternetConnection()
   if InternetState['RetCode']!=0:
      print (TextColorRed+InternetState['Description']+'\nImageMagick安装失败，程序退出！'+TextColorWhite)
      return 1
   subprocess.call('yum install openssl -y',shell=True)

   

   if  subprocess.call('rpm -Uvh --force install_package/rpm_rabbitmq/erlang/*.rpm',shell=True):
      print (TextColorRed+'erlang 组件安装失败,无法安装Rabbitmq，程序退出！'+TextColorWhite)
      AppInstalledState['rabbitmq']='not ok'
      exit(1)
   print (TextColorGreen+'erlang安装完毕.'+TextColorWhite)

   if subprocess.call('rpm -Uvh --force install_package/rpm_rabbitmq/rabbitmq/*.rpm',shell=True):
      print (TextColorRed+'Rabbitmq安装失败，程序退出.'+TextColorWhite)
      AppInstalledState['rabbitmq']='not ok'
      exit(1)
   print (TextColorGreen+'Rabbitmq 安装完毕.'+TextColorWhite)
   AppInstalledState['rabbitmq']='ok'
   print (TextColorGreen+'请访问如下地址，完成Rabbitmq 后续的配置操作\n'+WikiURL+TextColorWhite)

#### 配置Rabbitmq 待续 #####




def checkMysqlVariables():
    ###   检查MYSQL  字符集 最大并发连接数  大小写忽略 参数的配置情况 ####
    try:
        host=raw_input('输入MYSQL IP(默认127.0.0.1):')
        host=host.strip()
        if len(host)==0:
            host='127.0.0.1'

        port=raw_input('输入MYSQL 端口（默认 3306）：')
        port=port.strip()
        if len(port)==0:
            port='3306'

        while True:
            user=raw_input('请输入MYSQL 连接用户名(不能为空)：')
            user=user.strip()
            if len(user)==0:
                continue
            else:
                break

        password=raw_input('请输入MYSQL 连接密码：')
        password=password.strip()
    except:
        return 1


    try:
        import mysql.connector
        ConnObj=mysql.connector.connect(host=host,port=port,user=user,password=password,connection_timeout=3)
    except Exception as e:
        print (TextColorRed+'连接Mysql 数据库失败，无法检查参数.'+TextColorWhite)
        print (TextColorRed+str(e)+TextColorWhite)
        return 1
    CursorObj=ConnObj.cursor()

    ### 检查character set 是否是UTF-8   ##
    CursorObj.execute("show variables like '%character_set%';")
    print ('########  字符集检查结果: #########')
    for item in CursorObj:
        if item[0]==u'character_set_filesystem' or item[0]==u'character_sets_dir':
            continue
        else:
            if item[1]!=u'utf8':
                print (TextColorRed+item[0]+' : '+item[1]+u' 异常'+TextColorWhite)
                continue
            print (TextColorGreen+item[0]+' : '+item[1]+u' 正确'+TextColorWhite)
    print ('########  END #########\n')

    ####  检查忽略大小写 ####
    CursorObj.execute("show variables like '%lower_case_table_names%';")
    TmpResult=CursorObj.fetchone()
    if TmpResult[1]==u'1':
        print (TextColorWhite+'Mysql大小写敏感配置： 正确'+TextColorWhite)
    else:
        print (TextColorRed+'Mysql大小写敏感配置： 异常'+TextColorWhite)

    ###   最大连接数   ###
    CursorObj.execute("show variables like 'max_connections';")
    TmpResult=int(CursorObj.fetchone()[1])

    if TmpResult<1000:
        print (TextColorRed+'Mysql 最大连接数配置：  异常'+TextColorWhite)
    else:
        print (TextColorGreen+'Mysql 最大连接数配置:  正确'+TextColorWhite)




def installMariadb():
    print ('安装说明：')
    print ('1、本工具通过解压二进制包方式安装Mariadb(版本：mariadb-10.2.10)')
    print ('2、 如果服务器能够连接互联网,请联网安装最新的版本！\n')
    print ('重要说明：')
    print ('A、 使用本工具安装MariaDB前，请务必确保当前服务器未安装其他版本 MYSQL 或者其他版本 MariaDB;')
    print ('B、 MariaDB 安装路径为: /usr/local/mysql')
    print ('C、 MariaDB 数据目录为:  /var/lib/mysql')
    print ('D、 MariaDB 配置文件为:  /etc/my.cnf')
    print ('安装前请务必确认以上路径未被占用，否则存在数据丢失风险!')
    while True:
        choice=raw_input('是否接受以上条款，并继续安装(Yes/No): ')
        choice=choice.strip().upper()
        if choice=='YES' or choice=='Y':
            break
        elif choice=='NO' or choice=='N':
            return
    if path.isfile('/etc/my.cnf'):
        with open('/etc/my.cnf',mode='rb') as f:
            TmpContent=f.read()

        TmpHashObj=hashlib.md5(TmpContent)
        if not TmpHashObj.hexdigest()=='dd87c1c409c896e2162a95954f3ded4e':
            print (TextColorRed+'检测到 /etc/my.cnf 配置文件，安装失败，程序退出'+TextColorWhite)
            AppInstalledState['mariadb']='not ok'
            exit(1)
        print (TextColorGreen+'/etc/my.cnf 文件冲突检测：通过'+TextColorWhite)

    TmpResult=checkPortState('127.0.0.1',3306)
    if TmpResult['RetCode']==0:
        print (TextColorRed+'检测到 3306 端口处于监听状态，安装失败，程序退出'+TextColorWhite)
        AppInstalledState['mariadb']='not ok'
        exit(1)
    print (TextColorGreen+'3306 端口检测：通过'+TextColorWhite)

    if path.isdir('/usr/local/mysql') or path.isdir('/var/lib/mysql'):
        print (TextColorRed+'/usr/local/mysql 或 /var/lib/mysql 目录已经存在 ，安装失败，程序退出'+TextColorWhite)
        AppInstalledState['mariadb']='not ok'
        exit(1)
    print (TextColorGreen+'/usr/local/mysql 及 /var/lib/mysql 目录冲突检测： 通过')

    if subprocess.call('yum install libaio* -y',shell=True):
        print (TextColorRed+'无法安装 libaio 组件，安装MariaDB 失败，程序退出'+TextColorWhite)
        AppInstalledState['mariadb']='not ok'
        exit(1)
    print (TextColorWhite+'成功安装 libaio组件，程序继续'+TextColorWhite)

    if subprocess.call('cd install_package/mariadb_archive;sh install.sh',shell=True):
        print (TextColorRed+'MariaDB 安装失败，程序退出'+TextColorWhite)
        AppInstalledState['mariadb']='not ok'
        exit(1)

    print (TextColorGreen+'MariaDB 安装成功!'+TextColorWhite)
    print (TextColorWhite+'正在启动及配置MariaDB,请稍候.....'+TextColorWhite)
    subprocess.call('firewall-cmd --zone=public --add-port=3306/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --reload',shell=True)
    subprocess.call('systemctl start mysql',shell=True)
    sleep(3)

    isRunningFlag=False
    for i in range(10):
        TmpResult=checkPortState('127.0.0.1',3306)
        if TmpResult['RetCode']==0:
            print (TextColorWhite+'MariaDB  启动成功!'+TextColorWhite)
            isRunningFlag=True
            break
        print (TextColorWhite+'等待 MariaDB 启动.....'+TextColorWhite)
        sleep((i+1)*5)

    if not isRunningFlag:
        print (TextColorRed+'MariaDB 无法启动，程序退出!'+TextColorWhite)
        AppInstalledState['mariadb']='not ok'
        exit(1)

    ###  创建账号及database ###
    try:
        import mysql.connector
        ConnObj=mysql.connector.connect(host='127.0.0.1',port=3306,user='root',password='',connection_timeout=3)
        TmpCursor=ConnObj.cursor()
        TmpCursor.execute("create database aicsdb_demo;")
        TmpCursor.execute("grant all privileges on *.* to 'aics'@'%' identified by 'trs@admin';")
        TmpCursor.execute("grant all privileges on *.* to 'aics'@'127.0.0.1' identified by 'trs@admin';")
        TmpCursor.execute("grant all privileges on *.* to 'aics'@'localhost' identified by 'trs@admin';")
        print (TextColorGreen+'成功创建 Database 及 连接账号'+TextColorWhite)
    except Exception as e :
        print (TextColorRed+'无法连接 Mysql 创建Database及账号,程序退出.'+TextColorWhite)
        AppInstalledState['mariadb']='not ok'
        exit(1)


    if subprocess.call('which mysql',shell=True):
        subprocess.call("echo 'export PATH=${PATH}:/usr/local/mysql/bin'>>/etc/profile",
                            shell=True)
    AppInstalledState['mariadb']='ok'






def installOpenCV():
    if not subprocess.call('source /etc/profile;pkg-config opencv --cflags',shell=True):
        print (TextColorWhite+'OpenCV 已经安装，无需重复安装')
        return

    print (TextColorWhite+'即将部署openCV,请稍候...'+TextColorWhite)
    InternetState=checkInternetConnection()
    if InternetState['RetCode']!=0:
       print (TextColorRed+InternetState['Description']+TextColorWhite)
       print (TextColorRed+'OpenCV安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['opencv']='not ok'
       exit(1)
    print (TextColorGreen+'网络检测畅通,安装继续。'+TextColorWhite)

    if  subprocess.call('yum groupinstall "Development Tools" -y',shell=True):
       print (TextColorRed+'安装 Development tools 失败，程序退出。'+TextColorWhite)
       AppInstalledState['opencv']='not ok'
       exit(1)

    if subprocess.call("yum install cmake gcc gtk2-devel numpy pkconfig ant maven -y",shell=True):
        print (TextColorRed+'安装OpenCV 依赖包失败，程序退出。'+TextColorWhite)
        AppInstalledState['opencv']='not ok'
        exit(1)

    subprocess.call('ldconfig',shell=True)
    print (TextColorWhite+'创建 /TRS/APP目录'+TextColorWhite)
    subprocess.call('mkdir -p /TRS/APP',shell=True)

    subprocess.call('tar -C /TRS/APP -xvzf install_package/opencv-3.3.1.tar.gz',shell=True)
    subprocess.call('cd /TRS/APP/opencv-3.3.1;mkdir build',shell=True)
    if subprocess.call('cd /TRS/APP/opencv-3.3.1/build;cmake -D CMAKE_BUILD_TYPE=DEBUG -D CMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=OFF ..;make -j %s'%(CPUCores,),
                       shell=True):
        print (TextColorRed+'编译openCV 失败，程序退出'+TextColorWhite)
        AppInstalledState['opencv']='not ok'
        exit(1)
    print (TextColorWhite+'OpenCV 编译成功'+TextColorWhite)

    if subprocess.call('cd /TRS/APP/opencv-3.3.1/build;make install',shell=True):
        print (TextColorRed+'OpenCV 安装失败，程序退出.'+TextColorWhite)
        AppInstalledState['opencv']='not ok'
        exit(1)
    print (TextColorGreen+'成功编译安装OpenCV'+TextColorWhite)
    AppInstalledState['opencv']='ok'

    print (TextColorWhite+'配置OpenCV环境变量..'+TextColorWhite)
    subprocess.call("echo '/usr/local/lib/' > /etc/ld.so.conf.d/opencv.conf",shell=True)
    subprocess.call('ldconfig',shell=True)

    if not path.isfile(r'/etc/profile.trs.backup'):
        subprocess.call('cp /etc/profile /etc/profile.trs.backup',shell=True)

    TmpFileContent=''
    with open(r'/etc/profile',mode='r') as f:
        TmpFileContent=f.read()

    ReObjA=re.search(r'^\s*export\s+PKG_CONFIG_PATH\s*=\s*.*?\n',TmpFileContent,flags=re.MULTILINE)
    if not ReObjA:
        with open(r'/etc/profile',mode='a') as f:
            f.write('\n'+'export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig/'+'\n')



def installAnaconda():
    def __installViaExpectScript():
        import pexpect
        outfile=open(r'result.log',mode='w')
        child=pexpect.spawn('sh install_package/python_archive/Anaconda3-5.2.0-Linux-x86_64.sh',timeout=None,logfile=outfile)
        child.expect('.*>>>.*')
        print ('INFO: PRESS ENTER TO CONTINUE')
        child.sendline('')

        while True:
            print ('INFO: READ THE LICENCE ITEM')
            i=child.expect(['.*--More--.*','.*>>>.*','.*\r\n'])

            if i==0:
                child.sendline('')
                continue
            elif i==1:
                print ('ACCEPT LICIENCE')
                child.sendline('yes')
                break
            elif i==2:
                continue

        child.expect('.*>>>.*')
        print ('CONTINUE AS YES')
        child.sendline('')

        while True:
            i=child.expect(['instal.*?\r\n','.*?>>>.*?','.*\r\n'])

            if i==0:
                print ('installing +++++++')
                continue
            elif i==1:
                print ('finish install ++++++++')
                child.sendline('yes')
                break
            else:
                continue

        while True:
            i=child.expect(['.*?>>>.*?','.*\r\n'])

            if i==0:
                print ('skip install CODE..')
                child.sendline('no')
                sleep (2)
                break
            elif i==1:
                continue



    if not subprocess.call('/root/anaconda3/bin/python  --version',shell=True):
        print (TextColorWhite+'Anaconda python 已经安装，无需重复安装'+TextColorWhite)
        return

    print (TextColorWhite+'即将安装Anaconda Python ，请稍候....'+TextColorWhite)
    InternetState=checkInternetConnection()
    if InternetState['RetCode']!=0:
       print (TextColorRed+InternetState['Description']+TextColorWhite)
       print (TextColorRed+'Anaconda Python安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['python3']='not ok'
       exit(1)
    print (TextColorGreen+'网络检测畅通,安装继续。'+TextColorWhite)

    if subprocess.call('yum install bzip2  -y',shell=True):
        print (TextColorRed+'安装Anaconda 依赖失败，程序退出'+TextColorWhite)
        exit(1)

    #### 交互安装Anaconda  ###
    __installViaExpectScript()
    subprocess.call('source /root/.bashrc',shell=True)
#    subprocess.call('mv /root/anaconda3/lib/python3.6/site-packages  /root/anaconda3/lib/python3.6/site-packages.backup',shell=True)
#    subprocess.call('tar -C /root/anaconda3/lib/python3.6 -xvzf install_package/python_archive/site-packages.tar.gz',shell=True)
    print (TextColorGreen+'成功安装Anaconda python'+TextColorWhite)
    AppInstalledState['python3']='ok'

    #### 安装 pdf2image   ##
    subprocess.call('cd  install_package/python_archive;tar  -xvzf Pillow-master.tar.gz',shell=True)
    subprocess.call('cd install_package/python_archive;tar  -xvzf poppler.tar.gz',shell=True)
    subprocess.call('cd install_package/python_archive;tar -xvzf pdf2image-master.tar.gz',shell=True)

    if subprocess.call('cd install_package/python_archive/poppler;yum localinstall poppler-0.26.5-20.el7.x86_64.rpm   -y',shell=True):
        print (TextColorRed+'安装 poppler 失败，程序退出'+TextColorWhite)
        exit(1)

    if subprocess.call('yum install gcc -y',shell=True):
        print (TextColorRed+'安装gcc 失败,无法安装 Pillow,程序退出.'+TextColorWhite)
        AppInstalledState['python3']='not ok'
        exit(1)
    if subprocess.call('cd install_package/python_archive/Pillow-master;/root/anaconda3/bin/python setup.py install',shell=True):
        print (TextColorRed+'安装 Pillow 失败，程序退出'+TextColorWhite)
        exit(1)

    if subprocess.call('cd install_package/python_archive/pdf2image-master;/root/anaconda3/bin/python setup.py install',shell=True):
        print (TextColorRed+'安装 pdf2image 失败，程序退出'+TextColorWhite)
        exit(1)




def installClickhouse():
    if not subprocess.call('which clickhouse-client',shell=True):
        print (TextColorWhite+'Clickhouse 已经安装，无需重复安装'+TextColorWhite)
        return

    print (TextColorWhite+'即将安装Clickhouse，请稍候.....'+TextColorWhite)
    InternetState=checkInternetConnection()
    if InternetState['RetCode']!=0:
       print (TextColorRed+InternetState['Description']+TextColorWhite)
       print (TextColorRed+'Clickhouse 安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['Clickhouse']='not ok'
       exit(1)
    print (TextColorGreen+'网络检测畅通,安装继续。'+TextColorWhite)

    if  subprocess.call('yum localinstall install_package/clickhouse/*.rpm -y',shell=True):
        print (TextColorRed+'安装 Clickhouse 失败，程序退出.'+TextColorWhite)
        AppInstalledState['clickhouse']='not ok'
        exit(1)

    subprocess.call('systemctl  enable clickhouse-server',shell=True)
    subprocess.call('firewall-cmd --add-port=8123/tcp --zone=public --permanent',shell=True)
    subprocess.call('firewall-cmd --reload',shell=True)

    TmpFileContent=''
    with open(r'install_package/clickhouse/config.xml',mode='r') as f:
        TmpFileContent=f.read()

    with open(r'/etc/clickhouse-server/config.xml',mode='w') as f:
        f.write(TmpFileContent)

    subprocess.call('systemctl start clickhouse-server',shell=True)

    print (TextColorWhite+'成功安装 Clickhouse'+TextColorWhite)
    AppInstalledState['clickhouse']='ok'


def installNeo4j():
    if not subprocess.call('which neo4j',shell=True):
        print (TextColorWhite+'Neo4j 已经安装，无需重复安装.'+TextColorWhite)
        return

    print (TextColorWhite+'即将安装 Neo4j ,请稍候....'+TextColorWhite)
    InternetState=checkInternetConnection()
    if InternetState['RetCode']!=0:
       print (TextColorRed+InternetState['Description']+TextColorWhite)
       print (TextColorRed+'Neo4j 安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['Neo4j']='not ok'
       exit(1)
    print (TextColorGreen+'网络检测畅通,安装继续。'+TextColorWhite)

    if subprocess.call('yum localinstall -y install_package/neo4j/*.rpm',shell=True):
        print (TextColorRed+'安装Neo4j 失败，程序退出'+TextColorWhite)
        AppInstalledState['neo4j']='not ok'
        exit(1)

    TmpFileContent=''
    with open(r'install_package/neo4j/neo4j.conf',mode='r') as f:
        TmpFileContent=f.read()

    with open(r'/etc/neo4j/neo4j.conf',mode='w') as f:
        f.write(TmpFileContent)

    subprocess.call('systemctl start neo4j',shell=True)

    isRunningFlag=False
    for i in range(10):
        if not  subprocess.call('systemctl status neo4j',shell=True):
            print (TextColorWhite+'Neo4j  启动成功'+TextColorWhite)
            isRunningFlag=True
            break
        print (TextColorWhite+'等待Neo4j 启动，等待次数:'+str(i+1))
        sleep(5)

    if not isRunningFlag:
        print (TextColorRed+'无法启动Neo4j,程序退出'+TextColorWhite)
        AppInstalledState['neo4j']='not ok'
        exit(1)


    sleep(5)
    subprocess.call('sh install_package/neo4j/neo4j.sh',shell=True)

    subprocess.call('firewall-cmd --zone=public --add-port=7687/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=7473/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --zone=public --add-port=7474/tcp --permanent',shell=True)
    subprocess.call('firewall-cmd --reload',shell=True)

    print (TextColorGreen+'成功安装 Neo4j'+TextColorWhite)
    AppInstalledState['neo4j']='ok'





def __preInstall():
   __checkOSVersion()
   __installMysqlDriver4Python()
   __installPexpect()
 
   global EnableLocalYum 

   for index in range(len(sys.argv)):
       if sys.argv[index]=='-localyum':
          EnableLocalYum=True
          print (TextColorGreen+'当前开启了本地YUM 开关'+TextColorWhite)
          break  


   try:
      LocalIP=extractLocalIP()
      ### 读取之前已经安装的介质信息，避免重复安装  ###
      if path.isfile(str(LocalIP)+'.log'):
         InputFile=open(LocalIP+'.log',mode='r')
         for line in InputFile:
             TmpList=line.strip().split(':')
             if len(TmpList)>=2:
                name,value=str(TmpList[0]).strip().lower(),str(TmpList[1]).strip().lower()
                if (name in validAppNameList) and (value=='ok'):
                   AppInstalledState[name]=value
                else:
                   print (TextColorRed+'无效的内容'+line+TextColorWhite)
             else:
                 print (TextColorRed+'无效的内容'+line+TextColorWhite)
         InputFile.close() 
      
      checkRootPrivilege()
      configureServerArgument()
   except Exception as e:
      print (TextColorRed+'预安装过程出错：'+str(e)+TextColorWhite)
   finally:
      pass
      

def __postInstall():
    try:
     	LocalIP=extractLocalIP()
    	FileObj=open(str(LocalIP)+'.log',mode='w')
    	for appname in AppInstalledState:
            if AppInstalledState[appname]=='ok':
               FileObj.write(appname+': '+'ok'+'\n')
               continue
            else:
               pass
        FileObj.close()
    except Exception as e:
          print (str(e))
          FileObj.close()
    finally:
          print(TextColorGreen+'介质的安装日志结果保存在当前目录下的:'+str(LocalIP)+'.log'+'文件当中!'+TextColorWhite)


def RunMenu():
    try:
       while True:
          print (TextColorGreen+'#########  欢迎使用“海云系统”，本工具将帮助你完成基础介质的安装。  ######')
          print ('           1、安装 JAVA;')
          print ('           2、安装 OpenCV')
          print ('           3、安装 Anaconda Python3')
          print ('           4、安装 Elasticsearch;')
          print ('           5、安装 Logstash;')
          print ('           6、安装 Nginx;')
          print ('           7、安装 Neo4j')
          print ('           8、安装 ClickHouse')
          print ('           9、安装 MariaDB')
          print ('           0、退出安装;'+TextColorWhite)
          
          choice=raw_input('请输入数值序号:')
          choice=choice.strip()
    
          if choice=='1':
             if ('java' in AppInstalledState) and (AppInstalledState['java']=='ok'):
                 print (TextColorGreen+'JAVA 已经安装，无需重复安装'+TextColorWhite)
                 continue
             installJava()
          elif choice=='2':
             if ('opencv' in AppInstalledState) and (AppInstalledState['opencv']=='ok'):
                 print (TextColorGreen+'OpenCV 已经安装，无需重复安装'+TextColorWhite)
                 continue
             installOpenCV()
          elif  choice=='3':
             if ('python3' in AppInstalledState) and (AppInstalledState['python3']=='ok'):
                print (TextColorGreen+'Anaconda Python3 已经安装，无需重复安装'+TextColorWhite)
                continue
             installAnaconda()
          elif  choice=='4':
             if ('elasticsearch'  in AppInstalledState) and (AppInstalledState['elasticsearch']=='ok'):
                print (TextColorGreen+' Elasticsearch 已经安装，无需重复安装'+TextColorWhite)
                continue
             installElasticsearch()
          elif  choice=='5':
             if ('logstash'  in AppInstalledState) and (AppInstalledState['logstash']=='ok'):
                print (TextColorGreen+'Logstash 已经安装，无需重复安装'+TextColorWhite)
                continue
             installLogstash()
          elif choice=='6':
             if ('nginx' in AppInstalledState) and (AppInstalledState['nginx']=='ok'):
                print (TextColorGreen+'Nginx 已经安装，无需重复安装'+TextColorWhite)
                continue
             installNginx()
          elif choice=='7':
             if ('neo4j' in AppInstalledState) and (AppInstalledState['neo4j']=='ok'):
                print (TextColorGreen+'Neo4j 已经安装，无需重复安装'+TextColorWhite)
                continue
             installNeo4j()
          elif  choice=='8':
             if ('clickhouse'  in AppInstalledState) and (AppInstalledState['clickhouse']=='ok'):
                print (TextColorGreen+'ClickHouse 已经安装，无需重复安装'+TextColorWhite)
                continue
             installClickhouse()
          elif choice=='9':
              if ('mariadb' in AppInstalledState) and (AppInstalledState['mariadb']=='ok'):
                  print (TextColorGreen+'MariaDB 已经安装，无需重复安装'+TextColorWhite)
                  continue
              installMariadb()
          elif  choice=='0':
             exit(0)
    except Exception as e:
          print (str(e))
    finally:
          __postInstall()
             


if __name__=='__main__':
  try:
    __preInstall()
    RunMenu()
  except Exception as e:
    print (TextColorRed+'Error:'+str(e)+TextColorWhite)
  finally:
    __postInstall()
   
