from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/')
def index():
    return "Flask Memory Shell Test Environment"

@app.route('/e')
def e():
    a = eval(request.args.get('cmd', '0'))
    if a:
        return "1"
    else:
        return "0"

@app.route('/test')
def test():
    template = '''
        <h1>Test Page</h1>
        <p>{{ name }}</p>
    '''
    name = request.args.get('name', 'Guest')
    return render_template_string(template)

@app.route('/debug')
def debug():
    return str(app.url_map)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 