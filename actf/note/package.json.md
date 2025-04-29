# package.json 详解

在Node.js项目中，`package.json`文件是核心配置文件，下面是对当前项目package.json的详细解释：

```json
{
  "dependencies": {
    "body-parser": "^1.20.3",
    "dompurify": "^3.2.3",
    "ejs": "^3.1.10",
    "express": "^4.21.2",
    "express-session": "^1.18.1",
    "jsdom": "^26.0.0",
    "puppeteer": "^24.1.1"
  }
}
```

## 基础知识

`package.json`文件的主要作用：
- 记录项目依赖的包及其版本
- 定义项目元数据（名称、版本、描述等）
- 配置npm脚本命令
- 设置项目的行为和配置

## 各依赖包解释

该项目使用了以下Node.js包：

1. **body-parser (^1.20.3)**
   - 用途：解析HTTP请求体的中间件
   - 功能：处理JSON、表单数据等不同格式的请求内容
   - 在Express中使用：`app.use(bodyParser.json())`

2. **dompurify (^3.2.3)**
   - 用途：HTML净化库
   - 功能：防止XSS攻击，移除HTML/JavaScript中的危险代码
   - 通常与jsdom一起使用，用于服务器端净化HTML

3. **ejs (^3.1.10)**
   - 用途：嵌入式JavaScript模板引擎
   - 功能：将数据与模板结合生成HTML
   - 在Express中配置：`app.set('view engine', 'ejs')`

4. **express (^4.21.2)**
   - 用途：轻量级Web应用框架
   - 功能：简化路由处理、中间件集成等服务器端开发
   - 是本项目的核心框架

5. **express-session (^1.18.1)**
   - 用途：Express的会话管理中间件
   - 功能：处理用户会话，在请求之间存储用户数据
   - 配置示例：`app.use(session({secret: 'secret', resave: true}))`

6. **jsdom (^26.0.0)**
   - 用途：JavaScript实现的DOM环境
   - 功能：在Node.js中提供类似浏览器的DOM功能
   - 与dompurify配合使用，用于HTML处理

7. **puppeteer (^24.1.1)**
   - 用途：无头Chrome浏览器控制库
   - 功能：用于Web自动化测试、爬虫、截图等
   - 在CTF挑战中模拟用户访问网页

## 版本号说明

Node.js使用语义化版本规范（Semantic Versioning）：

- **格式**：主版本.次版本.补丁版本（例如1.2.3）
- **前缀符号**：
  - `^`：兼容性更新，允许更新到非破坏性的新版本（更新次版本和补丁版本）
  - `~`：补丁更新，只更新最小的版本号（仅更新补丁版本）
  - 无前缀：精确版本，固定使用指定版本

例如，对于`"express": "^4.21.2"`：
- 允许安装4.21.2或更高的4.x.x版本
- 但不会安装5.0.0或更高版本（主版本号变化可能有破坏性更改）

## 在开发中使用

安装所有依赖：
```bash
npm install
```

添加新依赖：
```bash
npm install 包名 --save
```

## 安全注意事项

在CTF挑战中，这些依赖可能存在漏洞或特定版本的问题，可以作为攻击向量。查找依赖中的安全问题：
```bash
npm audit
``` 