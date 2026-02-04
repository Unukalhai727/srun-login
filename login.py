from base64 import b64encode
from hashlib import md5, sha1
from hmac import new
import json
import logging
from time import time

import requests
from xxtea import xencode


class SrunManager:
    ac_id = "0"
    enc_ver = "srun_bx1"
    n = "200"
    type = "1"
    device = ["Windows", "Windows 10"]

    def __init__(self, host: str = "http://192.168.112.30"):
        self.host = host

    @staticmethod
    def _trans_b64encode(s: str) -> str:
        result = b64encode(s.encode(encoding='latin-1')).decode()
        alpha = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
        table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return result.translate(str.maketrans(table, alpha))

    def localhost(self) -> str:
        params = {
            "callback": "jQuery",
            "_": round(time() * 1000)
        }
        response = requests.get(f"{self.host}/cgi-bin/rad_user_info", params=params)
        ip: str = json.loads(response.text.strip("jQuery()"))["online_ip"]
        return ip

    def check(self, ip: str) -> bool:
        params = {
            "callback": "jQuery",
            "ip": ip,
            "_": round(time() * 1000)
        }
        response = requests.get(f"{self.host}/cgi-bin/rad_user_info", params=params)
        result: dict = json.loads(response.text.strip("jQuery()"))
        if result["error"] == "ok" and result["online_ip"] == ip:
            logging.info(f"{ip}已登录")
            return True
        else:
            logging.info(f"{ip}未登录")
            return False

    def login(self, username: str, password: str, ip: str) -> bool:
        # 1. 获取token
        params = {
            "callback": "jQuery",
            "username": username,
            "ip": ip,
            "_": round(time() * 1000)
        }
        response = requests.get(f"{self.host}/cgi-bin/get_challenge", params=params)
        token: str = json.loads(response.text.strip("jQuery()"))["challenge"]

        # 2. 构造加密参数
        password_md5 = new(token.encode(), password.encode(), md5).hexdigest()
        info_dict = {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": self.ac_id,
            "enc_ver": self.enc_ver,
        }
        info = "{SRBX1}" + self._trans_b64encode(xencode(json.dumps(info_dict), token))

        chksum  = token + username \
                + token + password_md5 \
                + token + self.ac_id \
                + token + ip \
                + token + self.n \
                + token + self.type \
                + token + info
        chksum = sha1(chksum.encode()).hexdigest()

        # 3. 发送登录请求
        params = {
            "callback": "jQuery",
            "action": "login",
            "username": username,
            "password": "{MD5}" + password_md5,
            "os": self.device[1],
            "name": self.device[0],
            "double_stack": "0",
            "chksum": chksum,
            "info": info,
            "ac_id": self.ac_id,
            "ip": ip,
            "n": self.n,
            "type": self.type,
            "_": round(time() * 1000),
        }
        response = requests.get(self.host + "/cgi-bin/srun_portal", params=params).text
        result: dict = json.loads(response.strip("jQuery()"))

        if result["error"] == "ok":
            logging.info(f"{username}@{ip}登录成功")
            return True
        else:
            match result["ecode"]:
                case "E2531":
                    logging.error(f"{username}@{ip}登录失败: 用户不存在")
                case "E2620":
                    logging.error(f"{username}@{ip}登录失败: 已经在线了")
                case "E2901":
                    logging.error(f"{username}@{ip}登录失败: 账号或密码错误")
                case "E2606":
                    logging.error(f"{username}@{ip}登录失败: 用户被禁用")
                case "":
                    logging.error(f"{username}@{ip}登录失败: 设备不存在")
                case _:
                    logging.error(f"{username}@{ip}登录失败: 未知错误")
            return False
