/**
 * bot.js - 模拟管理员行为的自动化脚本
 * 这个文件实现了一个自动化机器人，模拟管理员访问指定URL的行为
 * 在CTF挑战中，这通常是攻击者需要利用的目标（XSS、CSRF等攻击）
 */

// 导入必要的Node.js模块
const puppeteer = require('puppeteer')       // Puppeteer是一个Node.js库，提供高级API控制Chrome/Chromium
const process = require('process')           // 提供与当前Node.js进程交互的能力
const fs = require('fs')                     // 文件系统模块，用于读写文件

/**
 * 立即执行函数(IIFE)，用于获取FLAG
 * 这种模式(function(){...})()会立即执行函数并返回结果
 * 在CTF中，FLAG通常是需要获取的目标信息
 */
const FLAG = (() => {
    let flag = 'flag{test}'                  // 默认测试FLAG
    if (fs.existsSync('flag.txt')){          // 检查是否存在flag.txt文件
        flag = fs.readFileSync('flag.txt').toString()  // 如果存在，读取文件内容作为真正的FLAG
        fs.unlinkSync('flag.txt')            // 读取后删除文件，防止直接访问
    } 
    return flag                              // 返回FLAG值
})()

// 确定浏览器是否以无头模式运行
// process.env.PROD获取环境变量，??是空值合并运算符
// 双感叹号(!!)将任何值转换为布尔值
const HEADLESS = !!(process.env.PROD ?? false)

/**
 * 睡眠函数 - 暂停执行指定的秒数
 * @param {number} sec - 要等待的秒数
 * @returns {Promise} - 一个在指定时间后解析的Promise
 * 
 * 这是实现异步等待的常用模式：
 * 1. 创建一个新Promise
 * 2. 使用setTimeout在指定时间后调用resolve函数
 * 3. 返回Promise，可以与async/await一起使用
 */
const sleep = (sec) => new Promise(r => setTimeout(r, sec * 1000))

/**
 * 访问指定URL的主函数
 * 这个函数模拟管理员登录并访问用户提供的URL
 * @param {string} url - 要访问的URL
 * 
 * 在CTF挑战中，这通常是攻击的关键点：
 * 攻击者提供恶意URL，管理员(bot)访问，从而触发漏洞
 */
async function visit(url) {
    // 启动浏览器实例
    let browser = await puppeteer.launch({
        headless: HEADLESS,                  // 是否以无头模式运行(不显示界面)
        executablePath: '/usr/bin/chromium', // 指定Chrome/Chromium可执行文件路径
        args: ['--no-sandbox'],              // 浏览器启动参数，禁用沙箱增加权限(不安全但常见于CTF)
    })
    let page = await browser.newPage()       // 创建新的浏览器页面

    // 首先访问应用主页
    await page.goto('http://localhost:3000/')

    // 等待页面元素加载并填写表单
    await page.waitForSelector('#title')     // 等待标题输入框出现
    await page.type('#title', 'flag', {delay: 100})       // 输入标题"flag"
    await page.type('#content', FLAG, {delay: 100})       // 输入内容为FLAG(敏感信息)
    await page.click('#submit', {delay: 100})             // 点击提交按钮

    // 等待3秒，确保表单提交完成
    await sleep(3)
    console.log('visiting %s', url)          // 记录正在访问的URL

    // 访问用户提供的URL(可能是恶意URL)
    await page.goto(url)
    await sleep(30)                          // 等待30秒，给恶意脚本足够的执行时间
    await browser.close()                    // 关闭浏览器
}

// 导出visit函数，使其可以被其他文件导入
module.exports = {
    visit
}

/**
 * 安全漏洞说明(仅供学习):
 * 
 * 1. 这个机器人模拟了管理员创建包含FLAG的笔记，然后访问用户提供的URL
 * 2. 主要漏洞点:
 *    - 管理员创建了包含敏感信息(FLAG)的笔记
 *    - 管理员会访问攻击者控制的URL
 *    - 攻击者可以利用XSS或其他前端漏洞窃取管理员的笔记内容
 * 3. 常见攻击路径:
 *    - 在网站上发现XSS漏洞
 *    - 构造恶意URL让管理员访问
 *    - 当管理员访问时，恶意脚本执行并窃取敏感信息
 *    - 将敏感信息发送到攻击者控制的服务器
 */