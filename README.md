# 保存米家智能门铃视频到本地

## 程序介绍

小米智能门铃的视频，在不开VIP的情况下，只能实现3天滚动存储，如果要实现更长周期的存储，费用并不便宜。
本程序通过登录米家账号，可定时将门铃的视频存到指定位置，如果存储空间足够，可以实现无限期视频存储。

## 使用方法

### 第一步，修改配置文件:config.json
```JSON
{
  "username": "米家账号用户名",
  "password": "米家账号密码",
  "save_path": "存储视频的路径",
  "schedule_minutes": 多少分钟运行一次,
  "ffmpeg": "ffmpeg的全路径",
  "merge": 是否合并视频true/false
}
```

* 如果启用视频合并的话，则需要本地安装有ffmpeg，启用后会将分片的ts视频合并和转码成mp4视频

### 第二步， 运行本程序
* 方法1： 本地运行(要求python3.8以上)
```bash
pip install -r requirements.txt
python main.py
```

* 方法2： 以Docker方法运行
```bash
docker compose up -d
```
