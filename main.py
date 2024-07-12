import sys

import xiaomi_cloud
from doorbell import MiDoorbell
import config
import schedule
import time
import json
import os
import logging

_LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


def check_and_download():
    try:
        # 登录米家账号
        cloud = xiaomi_cloud.MiotCloud(username=conf.username, password=conf.password)
        cloud.login()
        _LOGGER.info('登录米家账号成功')

        # 获取米家设备列表
        device_list = cloud.get_device_list()
        _LOGGER.info('共获取到%d个设备', len(device_list))

        # 匹配智能门铃设备
        _LOGGER.info('正在自动匹配智能门铃设备...')
        device = None
        for d in device_list:
            # 自动匹配设备类型
            if d['model'].startswith('madv.cateye.'):
                device = d
                break

        if not device:
            # 未找到门铃设备
            _LOGGER.error('未找到米家智能门铃,请确认以下设备是否包含智能门铃：')
            for device in device_list:
                _LOGGER.error('%s(%s)', device['name'], device['model'])
            sys.exit(1)

        cam = MiDoorbell(cloud, device['name'], device['did'], device['model'])
        _LOGGER.info('匹配门铃设备成功，设备名称为:%s(%s)', cam.name, cam.model)

        # 读取已经处理过的视频，避免重复处理
        data = {}
        data_path = './data.json'
        if os.path.exists(data_path):
            with open(data_path, 'r') as f:
                data = json.load(f)

        # 获取门铃事件列表(过滤历史已处理)
        event_list = [event for event in cam.get_event_list() if event.fileId not in data]
        _LOGGER.info('本次共获取到%d条门铃事件', len(event_list))

        # 处理并下载视频
        for event in event_list:
            data[event.fileId] = event._asdict()

            _LOGGER.info(event.event_desc() + ',视频下载中...')
            # 保存视频到指定文件
            path = cam.download_video(event, conf.save_path, conf.merge, conf.ffmpeg)
            _LOGGER.info('视频已保存到：%s', path)

        # 存储已经处理过的记录
        with open(data_path, 'w') as fp:
            json.dump(data, fp, ensure_ascii=False, indent=True)
        _LOGGER.info('本次共处理%d条门铃事件, 历史总处理%d条门铃事件', len(event_list), len(data))
    except Exception as e:
        _LOGGER.error('出错了:%s', e)

    return ''


if __name__ == '__main__':
    conf = config.from_file()

    # 检查并下载视频
    check_and_download()

    # 定时执行
    schedule.every(conf.schedule_minutes).minutes.do(check_and_download)

    while True:
        schedule.run_pending()
        time.sleep(1)
