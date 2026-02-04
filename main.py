from argparse import ArgumentParser
import json
import logging
from login import SrunManager


args = ArgumentParser()
args.add_argument("-c", "--config", type=str, required=True, help="Path to userinfo.json")
args = args.parse_args()

logging.basicConfig(level=logging.INFO, format="%(message)s")
config = json.load(open(args.config))
client = SrunManager()
for item in config["device"]:
    if client.check(item["ip"]):
        continue
    client.login(item["account"], config["account"][item["account"]], item["ip"])
