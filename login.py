from hashlib import md5, sha1
from hmac import new
from json import loads, dumps
import logging
from time import time

from requests import Session
from encode import b64encode, xencode


class Manager(Session):
    acid = 0
    n = "200"
    vtype = "1"
    enc_ver = "srun_bx1"
    host = "http://192.168.112.30"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 "
        " Safari/537.36 Edg/128.0.0.0"
    }
    device = ["Windows 10", "Windows"]

    def __init__(self, name: str, ip: str, username: str, password: str):
        super().__init__()
        self.name = name
        self.ip = ip
        self.username = username
        self.password = password

    def __call__(self, reconnect=False) -> bool:
        description = f"{self.name}({self.ip}) with {self.username}"

        # logout if reconnect
        if reconnect:
            callback = f"jQuery112405185119642573086_{round(time() * 1000)}"
            local_time = round(time())
            params = {
                "callback": callback,
                "username": self.username,
                "ip": self.ip,
                "time": local_time,
                "unbind": "1",
                "sign": sha1(f"{local_time}{self.username}{self.ip}1{local_time}".encode()).hexdigest(),
                "_": round(time() * 1000),
            }
            resp = self.get(f"{self.host}/cgi-bin/rad_user_dm", headers=self.headers, params=params).text
            result: dict = loads(resp.strip(callback + "()"))

            if result.get("error") == "ok":
                logging.info(f"{description} logout success")
                return True
            else:
                logging.error(f"{description} logout faild: unknow error")

            # get token
        callback = f"jQuery1124015280105355320628_{round(time() * 1000)}"
        params = {"callback": callback, "username": self.username, "ip": self.ip, "_": round(time() * 1000)}
        resp = self.get(f"{self.host}/cgi-bin/get_challenge", headers=self.headers, params=params).text
        result: dict = loads(resp.strip(callback + "()"))
        token = result["challenge"]
        logging.debug(f"Token: {token}")

        info_dict = {
            "username": self.username,
            "password": self.password,
            "ip": ip,
            "acid": str(self.acid),
            "enc_ver": self.enc_ver,
        }
        info = "{SRBX1}" + b64encode(xencode(dumps(info_dict), token))  # type: ignore
        password_md5 = new(token.encode(), self.password.encode(), md5).hexdigest()

        # get checksum
        checksum = token + self.username
        checksum += token + password_md5
        checksum += token + str(self.acid)
        checksum += token + self.ip
        checksum += token + self.n
        checksum += token + self.vtype
        checksum += token + info
        checksum = sha1(checksum.encode()).hexdigest()

        # send login request
        callback = f"jQuery1124015280105355320628_{round(time() * 1000)}"
        params = {
            "callback": callback,
            "action": "login",
            "username": self.username,
            "password": "{MD5}" + password_md5,
            "os": self.device[0],
            "name": self.device[1],
            "double_stack": "0",
            "chksum": checksum,
            "info": info,
            "ac_id": str(self.acid),
            "ip": self.ip,
            "n": self.n,
            "type": self.vtype,
            "_": round(time() * 1000),
        }
        resp = self.get(self.host + "/cgi-bin/srun_portal", headers=self.headers, params=params).text
        result: dict = loads(resp.strip(callback + "()"))

        if result.get("suc_msg"):
            logging.info(f"{description} login success")
            return True
        else:
            error_msg = str(result.get("error_msg"))
            if "E2620" in error_msg:
                logging.info(f"{description} are already online")
                return True
            if "BAS" in error_msg or "Nas" in error_msg:
                logging.error(f"{description} login faild: ac_id error")
            elif "E2901" in error_msg:
                logging.error(f"{description} login faild: username or password error")
            elif "E2606" in error_msg:
                logging.error(f"{description} login faild: user is disabled")
            else:
                logging.error(f"{description} login faild: unknow error")
            return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s",
                        handlers=[logging.FileHandler("login.log", mode="w", encoding="utf-8"), logging.StreamHandler()])
    config = loads(open("userinfo.json", "r", encoding="utf-8").read())
    logging.info("--- Auto Login Start ---")
    for device in config["device"]:
        name = device["description"]
        ip = device["ip"]
        username = device["account"]
        password = config["account"][username]
        Manager(name, ip, username, password)()
    logging.info("--- Auto Login Finished ---")
