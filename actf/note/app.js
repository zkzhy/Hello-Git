/**
 * 这是一个Express.js Web应用程序，实现了一个简单的笔记应用
 * 这个应用程序允许用户创建笔记，并将它们保存在内存中
 * 注意：这是一个CTF(Capture The Flag)挑战，包含有意设计的安全漏洞
 */

// 导入所需的Node.js模块
const express = require('express')              // Express是一个流行的Web框架，用于处理HTTP请求和响应
const session = require('express-session')      // 用于管理用户会话，存储用户特定的数据
const { randomBytes } = require('crypto')       // Node.js内置的加密模块，这里用来生成随机字节
const fs = require('fs')                        // 文件系统模块，用于文件读写操作
const spawn = require('child_process')          // 用于创建子进程，这里用来执行shell命令
const path = require('path')                    // 用于处理文件路径
const { visit } = require('./bot')              // 导入自定义bot模块，用于访问URL（可能是用于模拟管理员访问）
const createDOMPurify = require('dompurify')    // 用于净化HTML，防止XSS攻击
const { JSDOM } = require('jsdom')              // 用于在Node.js中模拟浏览器环境

// 创建DOMPurify实例，用于HTML净化
// JSDOM()创建一个虚拟DOM环境，DOMPurify需要这个环境来工作
const DOMPurify = createDOMPurify(new JSDOM('').window)

// 设置服务器监听的端口和主机
const LISTEN_PORT = 3000                        // 服务器将监听的端口号
const LISTEN_HOST = '0.0.0.0'                   // 服务器将监听的IP地址，0.0.0.0表示所有可用网络接口

// 创建Express应用实例
const app = express()

// 设置视图引擎和视图目录
app.set('views', './views')                     // 告诉Express在哪里查找视图/模板文件
app.set('view engine', 'html')                  // 设置视图引擎为html
app.engine('html', require('ejs').renderFile)   // 使用EJS模板引擎来渲染.html文件

// 配置中间件
app.use(express.urlencoded({ extended: true })) // 解析application/x-www-form-urlencoded格式的请求体

// 配置会话中间件
app.use(session({
    secret: randomBytes(4).toString('hex'),     // 会话加密密钥（随机生成）
    saveUninitialized: true,                    // 即使未初始化的会话也保存
    resave: true,                               // 即使会话没有修改也重新保存
}))

// 自定义中间件：确保每个用户会话都有一个空的笔记数组
app.use((req, res, next) => {
    if (!req.session.notes) {                   // 如果会话中没有notes属性
        req.session.notes = []                  // 初始化为空数组
    }
    next()                                      // 调用下一个中间件或路由处理程序
})

// 在内存中存储笔记内容的Map对象
// 键是笔记ID，值是笔记对象（包含标题和内容）
const notes = new Map()

// 设置定时器，每分钟清理一次notes映射
// 这意味着所有笔记将在60秒后从内存中删除
setInterval(() => { notes.clear() }, 60 * 1000)

/**
 * 将源文本转换为HTML
 * @param {string} source - 要转换的源文本
 * @param {string} format - 源文本的格式，默认为'markdown'
 * @returns {string} - 转换后的HTML，经过DOMPurify净化
 * 
 * 注意：这个函数存在命令注入漏洞，因为它直接使用用户输入执行shell命令
 */
function toHtml(source, format){
    if (format == undefined) {
        format = 'markdown'                     // 如果未指定格式，默认使用markdown
    }
    let tmpfile = path.join('notes', randomBytes(4).toString('hex'))  // 创建临时文件路径
    fs.writeFileSync(tmpfile, source)           // 将源文本写入临时文件
    
    // 安全漏洞：直接将用户提供的format参数传入shell命令
    // 使用pandoc(一个文档转换工具)将源文本转换为HTML
    let res = spawn.execSync(`pandoc -f ${format} ${tmpfile}`).toString()
    
    // 注释掉了删除临时文件的代码，可能导致临时文件堆积
    // fs.unlinkSync(tmpfile)
    
    // 使用DOMPurify净化HTML，防止XSS攻击
    return DOMPurify.sanitize(res)
}

// 路由定义

// 简单的健康检查路由
app.get('/ping', (req, res) => {
    res.send('pong')                            // 返回"pong"文本
})

// 首页路由
app.get('/', (req, res) => {
    // 渲染index视图，并传递用户会话中的笔记数组
    res.render('index', { notes: req.session.notes })
})

// 获取用户所有笔记ID的路由
app.get('/notes', (req, res) => {
    res.send(req.session.notes)                 // 返回用户会话中保存的笔记ID数组
})

// 查看特定笔记的路由
app.get('/note/:noteId', (req, res) => {
    let { noteId } = req.params                 // 从URL参数中提取笔记ID
    if(!notes.has(noteId)){                     // 检查笔记ID是否存在
        res.send('no such note')                // 如果不存在，返回错误消息
        return
    } 
    let note = notes.get(noteId)                // 获取笔记对象
    res.render('note', note)                    // 渲染note视图，并传递笔记对象
})

// 创建新笔记的路由
app.post('/note', (req, res) => {
    let noteId = randomBytes(8).toString('hex') // 生成随机的笔记ID
    let { title, content, format } = req.body   // 从请求体中提取标题、内容和格式
    
    // 验证format参数：只允许1-10个字母数字字符
    if (!/^[0-9a-zA-Z]{1,10}$/.test(format)) {
        res.send("illegal format!!!")           // 如果格式不符合要求，返回错误消息
        return
    }
    
    // 将笔记保存到内存中
    notes.set(noteId, {
        title: title,
        content: toHtml(content, format)        // 调用toHtml函数将内容转换为HTML
    })
    
    req.session.notes.push(noteId)              // 将新笔记的ID添加到用户会话中
    res.send(noteId)                            // 返回新创建的笔记ID
})

// 报告页面路由
app.get('/report', (req, res) => {
    res.render('report')                        // 渲染report视图
})

// 提交报告的路由
app.post('/report', async (req, res) => {
    let { url } = req.body                      // 从请求体中提取URL
    try {
        await visit(url)                        // 调用bot模块的visit函数访问URL（模拟管理员访问）
        res.send('success')                     // 如果成功，返回"success"
    } catch (err) {
        console.log(err)                        // 如果出错，记录错误
        res.send('error')                       // 返回"error"
    }
})

// 启动服务器
app.listen(LISTEN_PORT, LISTEN_HOST, () => {
    console.log(`listening on ${LISTEN_HOST}:${LISTEN_PORT}`)  // 服务器启动成功后的日志
})

/**
 * 安全漏洞分析（仅用于学习目的）：
 * 
 * 1. 命令注入漏洞：
 *    - toHtml函数中直接将用户提供的format参数拼接到shell命令中
 *    - 尽管有基本的正则表达式检查，但仍可能存在bypass方法
 * 
 * 2. 临时文件未删除：
 *    - 创建的临时文件未被删除(fs.unlinkSync被注释掉)
 *    - 可能导致敏感信息泄露或磁盘空间耗尽
 * 
 * 3. 会话安全性：
 *    - 使用随机生成的secret，但在每次启动时都会变化
 *    - 这可能导致用户重启服务器后登录状态丢失
 * 
 * 4. 潜在的SSRF漏洞：
 *    - /report路由允许访问任意URL
 *    - 可能被用于探测内部网络或访问内部服务
 */
