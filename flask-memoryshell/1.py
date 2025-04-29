from flask import Flask, request, render_template_string
import os

# 创建Flask应用实例
app = Flask(__name__)

@app.route('/')
def index():
    """主页路由，返回简单的欢迎信息"""
    return "Flask Memory Shell Test Environment"

@app.route('/e')
def e():
    """
    危险的路由 - 包含任意代码执行漏洞
    通过eval函数直接执行用户提供的cmd参数
    这是植入内存马的主要入口点
    """
    a = eval(request.args.get('cmd', '0'))  # 危险：直接eval用户输入
    if a:
        return "1"  # 如果执行成功返回1
    else:
        return "0"  # 如果执行失败或返回False/None则返回0

@app.route('/test')
def test():
    """
    包含服务器端模板注入(SSTI)漏洞的路由
    用户提供的name参数直接被插入到模板中并渲染
    可以用于执行模板注入攻击
    """
    template = '''
        <h1>Test Page</h1>
        <p>{{ name }}</p>
    '''
    name = request.args.get('name', 'Guest')  # 用户输入未经过滤
    # 危险：直接将用户输入渲染为模板
    return render_template_string(template)  

@app.route('/debug')
def debug():
    """
    调试路由，显示所有注册的URL规则
    用于验证add_url_rule方法是否成功添加了新路由
    """
    return str(app.url_map)

if __name__ == '__main__':
    # 启动Flask应用
    # debug=True开启调试模式，便于查看错误信息
    # 注意：生产环境中应关闭debug模式
    app.run(host='127.0.0.1', port=5000, debug=True)