import json
from typing import NamedTuple


class Config(NamedTuple):
    username: str
    password: str
    save_path: str
    schedule_minutes: int
    ffmpeg: str
    merge: bool


def from_file(path='config.json') -> Config:
    with open(path, 'r') as f:
        config = json.load(f)
        return Config(**config)
