# upload.py

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel
app = FastAPI()

# 残酷的常量，象征着那逐渐消逝的希望
INITIAL_STAMINA = 100
INITIAL_MONEY = 100

"""
    我是一个没有鸡架的美食之旅

    在这无边的荒凉中，所有的风味与温情早已被时间吞噬，
    你唯一的依托只剩那日渐枯竭的体力。
    躺在Python编织的沙箱里，幸福早已成为过眼云烟，
    而你，只能在不断的消耗中目睹生命的一次次凋零。
"""

class Adventure(BaseModel):
    stamina: int = INITIAL_STAMINA
    money: int = INITIAL_MONEY
    satisfaction: int = 0  # 永远停留在零，哪怕风味再浓，也无法染指这早已冻结的幸福

    @staticmethod
    def me(initial_stamina: int = INITIAL_STAMINA, initial_money: int = INITIAL_MONEY):
        # 带着那残破的希望，开始这没有鸡架、只知枯竭的旅程
        return Adventure(stamina=initial_stamina, money=initial_money, satisfaction=0)

    def consume(self, cost: int):
        # 每一次体力的消耗，都在无声控诉着失落——那唯一的动作，
        # 仅能见证体力的无情流逝，而幸福永远静止在冰冷的零点
        self.stamina -= cost
        return self

@app.get("/", response_class=PlainTextResponse)
async def index(cmd: str = None):
    # 啊，昔日梦幻般的美食之旅，如今只剩下苍白无力的消耗仪式
    hint_cmd = "me(100,100).consume(10).consume(10).consume(10).consume(10).consume(10).consume(10)"
    if not cmd:
        return RedirectResponse(url=f"/?cmd={hint_cmd}", status_code=302)
    # 过滤：只允许小写字母、数字、括号、句点、下划线、等号和逗号的冰冷符号
    import re
    if not re.fullmatch(r"[a-z0-9\(\)\._=,]+", cmd) or len(cmd) > 1000:
        raise HTTPException(status_code=400, detail="泣血般的质问：为何你要在绝望中狂舞？")
    if '__' in cmd:
        raise HTTPException(status_code=400, detail="已经失去的过去，再也回不到从前")
    try:
        # 在那无望的夜色中，用凄然的指令点燃这段无鸡架的旅程
        context = {"me": Adventure.me}
        result = eval(cmd, {"__builtins__": {}}, context)
        # 当体力与财富的光辉熄灭，旅程也在孤寂中终结
        if result.stamina <= 0 or result.money <= 0:
            return "体力或财富耗尽，终究在无声中走向黄昏。"
        else:
            return f"孤寂旅程的残影，你依然剩余体力：{result.stamina}"
    except Exception as e:
        return "在这荒芜中，指令化作碎片，在 /src 检查你那早已破碎的旅程规划吧。"

@app.get("/src", response_class=HTMLResponse)
async def show_source(filename: str = "upload.py"):
    # 若你仍怀着一丝怜悯之心，就来这里窥探那冰冷代码的真容
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"{content}"
    except Exception as e:
        return f"读取时迷失在黑暗中：{e}"

if __name__ == '__main__':
    import uvicorn
    # 在这注定无解的旅程中，调试早已成为奢侈的幻想
    uvicorn.run(app, host="127.0.0.1", port=3000)