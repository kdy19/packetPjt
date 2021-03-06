from flask import Flask
from flask import request
from flask import make_response
from flask import render_template

import psutil

from analy import analysis

import multiprocessing
import hashlib
import sqlite3
import random
import shutil
import time
import json
import os


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024


def color() -> list:
    rgb_border_list = list()
    rgb_back_list = list()

    for i in range(0, 4):
        tmp_border = list()
        tmp_back = list()
        for j in range(0, 10):
            rgb1 = random.randint(0, 255)
            rgb2 = random.randint(0, 255)
            rgb3 = random.randint(0, 255)

            tmp_border.append(f'rgba({rgb1}, {rgb2}, {rgb3}, 1)')
            tmp_back.append(f'rgba({rgb1}, {rgb2}, {rgb3}, 0.2)')

        rgb_border_list.append(tmp_border)
        rgb_back_list.append(tmp_back)

    return rgb_border_list, rgb_back_list


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/live-data')
def live_data():
    cpu_used = psutil.cpu_percent()
    hw_information = [[time.time()*1000, cpu_used],
                      [time.time()*1000, round(psutil.virtual_memory().used/1024/1024/1024, 1)]]

    response = make_response(json.dumps(hw_information))
    response.content_type = 'application/json'
    return response


@app.route('/submit', methods=['POST'])
def file_upload():
    if request.method == 'POST':
        f = request.files['file']
        f.save(f'./data/file/{f.filename}')

        with open(f'./data/file/{f.filename}', 'rb') as fi:
            data = fi.read()
            file_hash_sha256 = hashlib.sha256(data).hexdigest()

        if os.path.isfile(f'./data/json/{file_hash_sha256}.json'):
            os.remove(f'./data/file/{f.filename}')
            return f'''
                <script>
                    alert('기존 분석 파일이 존재합니다.');
                    location.href='/view/{file_hash_sha256}';
                </script>
            '''

        shutil.copy2(f'./data/file/{f.filename}', f'./data/file/{file_hash_sha256}')
        os.remove(f'./data/file/{f.filename}')

        p = multiprocessing.Process(target=analysis, args=(f.filename, file_hash_sha256,))
        p.start()

        return '''
            <script>
                alert('파일 등록이 완료되었습니다. 분석은 길게 10분까지 걸립니다.');
                location.href='/';
            </script>
        '''
    else:
        return render_template('index.html')


@app.route('/recent')
def recent():
    with sqlite3.connect('DB.db') as conn:
        cur = conn.cursor()
        sql_query = 'SELECT * FROM file_info'
        cur.execute(sql_query)

        data = cur.fetchall()
        data = data[::-1]

    return render_template('recent.html', data=data)


@app.route('/view/<filehash>')
def view(filehash):
    with open(f'./data/json/{filehash}.json', 'rt') as f:
        data = json.load(f)

    src_ip = list(data['info']['packet']['src_ip'].items())[:10]
    src_port = list(data['info']['packet']['src_port'].items())[:10]
    src_ip_port = list(data['info']['packet']['src_ip_port'].items())[:10]
    dst_ip = list(data['info']['packet']['dst_ip'].items())[:10]
    dst_port = list(data['info']['packet']['dst_port'].items())[:10]
    dst_ip_port = list(data['info']['packet']['dst_ip_port'].items())[:10]

    rgb_border_list, rgb_back_list = color()

    # RGB 4
    return render_template('view.html', src_ip=src_ip, src_port=src_port, src_ip_port=src_ip_port,
                           dst_ip=dst_ip, dst_port=dst_port, dst_ip_port=dst_ip_port,
                           rgb_border_list=rgb_border_list, rgb_back_list=rgb_back_list)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888)
