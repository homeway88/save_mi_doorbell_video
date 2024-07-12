from urllib.parse import urlencode
import logging
import time
from datetime import datetime
import locale
import binascii
import os

import requests
import subprocess
from Crypto.Cipher import AES
from typing import NamedTuple, List

_LOGGER = logging.getLogger(__name__)


class DoorbellEvent(NamedTuple):
    eventTime: int
    fileId: str
    eventType: str

    def date_time_fmt(self):
        t = datetime.fromtimestamp(float(self.eventTime) / 1000)
        return t.strftime('%Y-%m-%d %H:%M:%S')

    def short_time_fmt(self):
        t = datetime.fromtimestamp(float(self.eventTime) / 1000)
        return t.strftime('%H%M%S')

    def shot_date_fmt(self):
        t = datetime.fromtimestamp(float(self.eventTime) / 1000)
        return t.strftime('%Y%m%d')

    def event_type_name(self):
        if self.eventType == 'Pass':
            return '有人在门前经过'
        elif self.eventType == 'Pass:Stay':
            return '有人在门停留'
        elif self.eventType == 'Bell':
            return '有人按门铃'
        elif self.eventType == 'Pass:Bell':
            return '有人按门铃'
        else:
            return self.eventType

    def event_desc(self):
        return '%s %s' % (self.date_time_fmt(), self.event_type_name())


class MiDoorbell:

    def __init__(self, xiaomi_cloud, name, did, model):
        self.xiaomi_cloud = xiaomi_cloud
        self.name = name
        self._state_attrs = {}
        self.miot_did = did
        self.model = model

    def get_event_list(self, start_time=None, end_time=None, limit=10) -> List[DoorbellEvent]:
        mic = self.xiaomi_cloud
        lag = locale.getlocale()[0]
        if start_time:
            stm = start_time
        else:
            stm = int(time.time() - 86400 * 1) * 1000

        if end_time:
            etm = end_time
        else:
            etm = int(time.time() * 1000 + 999)

        api = mic.get_api_by_host('business.smartcamera.api.io.mi.com', 'common/app/get/eventlist')
        rqd = {
            'did': self.miot_did,
            'model': self.model,
            'doorBell': True,
            'eventType': 'Default',
            'needMerge': True,
            'sortType': 'DESC',
            'region': str(mic.default_server).upper(),
            'language': lag,
            'beginTime': stm,
            'endTime': etm,
            'limit': limit,
        }

        all_list = []
        is_continue = True
        next_time = etm

        while is_continue:
            rqd['endTime'] = next_time

            rdt = mic.request_miot_api(api, rqd, method='GET', crypt=True) or {}
            data = rdt.get('data', {})
            is_continue = data['isContinue']
            next_time = data['nextTime']

            rls = data.get('thirdPartPlayUnits') or []

            for item in rls:
                all_list.append(DoorbellEvent(
                    eventTime=int(item['createTime']),
                    fileId=item['fileId'],
                    eventType=item['eventType']))

        return all_list

    def download_video(self, event: DoorbellEvent, save_path, merge=False, ffmpeg=None):
        m3u8_url = self.get_video_m3u8_url(event)
        resp = requests.get(m3u8_url)
        lines = resp.content.splitlines()
        video_cnt = 0
        key = None
        iv = None

        video_path = save_path + '/' + event.shot_date_fmt() + '/' + event.short_time_fmt()
        ts_path = video_path + '/ts'
        os.makedirs(video_path, exist_ok=True)
        os.makedirs(ts_path, exist_ok=True)

        # 保存文件的同时，生成文件清单到filelist
        with open(ts_path + '/filelist', 'w') as filelist:
            for line in lines:
                line = line.decode('utf-8')
                # 解析密钥信息
                if line.startswith('#EXT-X-KEY'):
                    start = line.index('URI="')
                    url = line[start: line.index('"', start + 10)][5:]
                    key = requests.get(url).content
                    iv = binascii.unhexlify(line[line.index('IV='):][5:])

                # 解析视频URL并下载
                if line.startswith('http'):
                    r = requests.get(line)
                    video_cnt += 1
                    crypto = AES.new(key, AES.MODE_CBC, iv)
                    filename = str(video_cnt) + '.ts'

                    with open(ts_path + '/' + filename, 'wb') as f:
                        f.write(crypto.decrypt(r.content))

                    # 添加文件名和列表中，方便ffmpeg做视频合并
                    filelist.writelines('file \'' + filename + '\'\n')

        if video_cnt > 0 and merge and ffmpeg:
            # 使用ffmpeg进行文件合并
            cmd = (ffmpeg + ' -f concat -i filelist -y -c:v libx264 -c:a aac ../' + event.short_time_fmt() + '.mp4').split(' ')
            subprocess.check_output(cmd, cwd=ts_path)
        return video_path

    def get_video_m3u8_url(self, event: DoorbellEvent):
        mic = self.xiaomi_cloud
        fid = event.fileId
        pms = {
            'did': str(self.miot_did),
            'model': self.model,
            'fileId': fid,
            'isAlarm': True,
            'videoCodec': 'H265',
        }
        api = mic.get_api_by_host('business.smartcamera.api.io.mi.com', 'common/app/m3u8')
        pms = mic.rc4_params('GET', api, {'data': mic.json_encode(pms)})
        pms['yetAnotherServiceToken'] = mic.service_token
        url = f'{api}?{urlencode(pms)}'
        return url
