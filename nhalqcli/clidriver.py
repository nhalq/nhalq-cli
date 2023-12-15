#!/usr/bin/python3

import pyzcommonlib
import argparse
import getpass
import hashlib
import io
import json
import pyotp
import re
import subprocess
import yaml

from Crypto import Random
from Crypto.Cipher import AES
from typing import *


class AESCipher:
    def __init__(self, password: str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(password.encode()).digest()

    def pad(self, s: str):
        remain = self.block_size - len(s) % self.block_size
        return s + remain * chr(remain)

    def unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, plain: str) -> bytes:
        plain = self.pad(plain)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(plain.encode())

    def decrypt(self, encrypted: bytes) -> str:
        iv = encrypted[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(encrypted[AES.block_size:])).decode("utf-8")


class VNGSecure:
    @staticmethod
    def passcode(pincode: str, secret: str):
        return pincode + pyotp.TOTP(secret).now()


class OpenVPN3CMD:
    @staticmethod
    def get_command_list():
        return ["status", "connect", "disconnect", "reconnect"]

    @staticmethod
    def parse_status_token(s: str) -> Dict[str, str]:
        tokens = list()
        while s and len(s):
            matched = re.search(r'\w+( \w+)*\:( [^\s]+)+', s)
            if not matched:
                break

            start, end = matched.start(), matched.end()
            k, v = map(str.strip, s[start:end].split(":", 1))

            tokens.append((k.replace(" ", "_").lower(), v))
            s = s[end:]

        return tokens

    @staticmethod
    def parse_status(row_iter: Iterable[str]) -> Dict[str, Any]:
        row = next(row_iter)
        while row:
            kvs = list()
            while row:
                if set(row) == set(['-']):
                    break

                kvs.append(OpenVPN3CMD.parse_status_token(row))
                row = next(row_iter)

            record = dict(sum(kvs, []))
            if "pid" in record:
                record["pid"] = int(record["pid"])

            yield record
            row = next(row_iter)

    @staticmethod
    def get_sessions() -> None:
        proc = subprocess.run(["openvpn3", "sessions-list"],
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

        if proc.returncode != 0:
            raise RuntimeError("".join(proc.stderr))

        return_str = proc.stdout.decode("utf-8")
        if return_str.startswith("No sessions available"):
            return []

        row_iter = map(str.rstrip, return_str.split("\n"))
        assert (set(next(row_iter)) == set(['-']))
        return list(OpenVPN3CMD.parse_status(row_iter))

    @staticmethod
    def connect(config_name: str, username: str, password: str) -> None:
        config_name = config_name.strip()

        sessions = OpenVPN3CMD.get_sessions()
        for session in sessions:
            session_config_name: str = session["config_name"]
            if session_config_name.startswith(config_name):
                raise RuntimeError("You are connected")

        proc = subprocess.Popen(["openvpn3", "session-start", "--config", config_name],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        proc.stdin.write((username + "\n" + password + "\n").encode())
        proc.stdin.flush()

        print("Connecting")
        proc.wait()

        if proc.returncode:
            raise RuntimeError("".join(map(bytes.decode, proc.stderr)))
        print("".join(map(bytes.decode, proc.stdout)))

    @staticmethod
    def disconnect(config: str) -> None:
        proc = subprocess.Popen(["openvpn3", "session-manage", "--disconnect", "--config", config],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        print(">>>> stdout")
        print("".join(map(bytes.decode, proc.stdout)))
        print(">>>> stderr")
        print("".join(map(bytes.decode, proc.stderr)))

    @staticmethod
    def reconnect(config: str) -> None:
        proc = subprocess.Popen(["openvpn3", "session-manage", "--restart", "--config", config],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        print(">>>> stdout")
        print("".join(map(bytes.decode, proc.stdout)))
        print(">>>> stderr")
        print("".join(map(bytes.decode, proc.stderr)))


def execute_of_vpn(args: argparse.Namespace) -> int:
    if args.action == "status":
        sessions = OpenVPN3CMD.get_sessions()
        print(json.dumps(sessions, indent=2))
        return 0

    with open("/etc/autobot/secret", "rb") as fs:
        encrypted_data = fs.read(2048)
    cipher = AESCipher(getpass.getpass("Enter your password: "))
    data = cipher.decrypt(encrypted_data).encode("utf-8")
    [profile] = yaml.safe_load(io.BytesIO(data))["profiles"]

    if args.action == "connect":
        password = VNGSecure.passcode(profile["pincode"], profile["secret"])
        OpenVPN3CMD.connect(profile["config"], profile["username"], password)
        return 0

    if args.action == "disconnect":
        OpenVPN3CMD.disconnect(profile["config"])
        return 0

    if args.action == "reconnect":
        OpenVPN3CMD.reconnect(profile["config"])
        return 0

    return (-1)


def execute_of_zdenoise(args: argparse.Namespace) -> int:
    try:
        item_id = pyzcommonlib.denoise_chunks(args.noise)
    except:
        try:
            item_id = pyzcommonlib.denoise_photo(args.noise)
        except:
            print("Can not denoise")
            return -1

    print("id:", item_id)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="qx")
    subparsers = parser.add_subparsers()

    vpn_subparser = subparsers.add_parser("vpn")
    vpn_subparser.set_defaults(execute=execute_of_vpn)
    vpn_subparser.add_argument("action", choices=(
        "status", "connect", "disconnect", "reconnect"))

    za_subparser = subparsers.add_parser("zdn")
    za_subparser.set_defaults(execute=execute_of_zdenoise)
    za_subparser.add_argument("noise")

    args = parser.parse_args()
    if not "execute" in args:
        parser.print_help()
        return -1

    return args.execute(args)
