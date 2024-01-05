import base64
import datetime
import json
import random
import string
from hashlib import md5
from threading import Thread


import time
from urllib.parse import urlparse

import requests
import tls_client
import ua_generator
from bs4 import BeautifulSoup

from utils.logger import MultiThreadLogger


def generate_random_number(length: int) -> int:
    return int(''.join([random.choice(string.digits) for _ in range(length)]))

def generate_csrf_token() -> str:
    random_int: int = generate_random_number(length=3)
    current_timestamp: int = int(str(int(datetime.datetime.now().timestamp())) + str(random_int))
    random_csrf_token = md5(string=f'{current_timestamp}:{current_timestamp},{0}:{0}'.encode()).hexdigest()

    return random_csrf_token


class YOGA:

    def __init__(self, proxy, tw_auth_token, tw_csrf, code, cap_key):

        self.InviteCode = code
        self.cap_key = cap_key

        self.defaultProxy = proxy
        proxy = proxy.split(':')
        proxy = f'http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}'

        self.proxy = {'http': proxy,
                      'https': proxy}

        self.auth_token = tw_auth_token
        self.csrf = tw_csrf

        self.session = self._make_scraper()
        self.session.proxies = self.proxy
        self.ua = ua_generator.generate().text

        self.session.headers.update({"user-agent": self.ua,
                                     "Origin":"https://well3.com"})




    def login(self):

        response = self.session.post("https://www.googleapis.com/identitytoolkit/v3/relyingparty/createAuthUri?key=AIzaSyBPmETcQFfpDrw_eB6s8DCkDpYYBt3e8Wg",
                                     json={"providerId":"twitter.com","continueUri":"https://auth.well3.com/__/auth/handler","customParameter":{}},
                                     headers={"X-Client-Data":"CPWCywE=",
                                              "content-type": "application/json"})
        # print(response.json())
        # input()
        authUrl = response.json()['authUri']
        sessionId = response.json()['sessionId']

        self.session.cookies.update({'auth_token': self.auth_token, 'ct0': self.csrf})
        response = self.session.get(authUrl)

        soup = BeautifulSoup(response.text, 'html.parser')
        # print(soup)
        #
        # input()
        authenticity_token = soup.find('input', attrs={'name': 'authenticity_token'}).get('value')

        payload = {'authenticity_token': authenticity_token,
                   'redirect_after_login': authUrl,
                   'oauth_token': authUrl.split("oauth_token=")[-1]}

        response = self.session.post(f'https://api.twitter.com/oauth/authorize', data=payload,
                                     headers={'content-type': 'application/x-www-form-urlencoded'})
        soup = BeautifulSoup(response.text, 'html.parser')

        link = soup.find('a', class_='maintain-context').get('href')

        response = self.session.post("https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=AIzaSyBPmETcQFfpDrw_eB6s8DCkDpYYBt3e8Wg",
                                     json={"requestUri":link,
                                           "sessionId":sessionId,
                                           "returnSecureToken":True,
                                           "returnIdpCredential":True},
                                     headers={"X-Client-Data": "CJjeygE=",
                                              "content-type": "application/json"})

        self.session.headers.update({"Authorization": response.json()['idToken']})

        response2 = self.session.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=AIzaSyBPmETcQFfpDrw_eB6s8DCkDpYYBt3e8Wg",
            json={"idToken": response.json()['idToken']},
            headers={"X-Client-Data": "CJjeygE=",
                     "content-type": "application/json"})

        response2 = self.session.post("https://api.gm.io/ygpz/link-twitter",
                                      json={"oauth":{"oauthAccessToken":response.json()['oauthAccessToken'],
                                                     "oauthTokenSecret":response.json()['oauthTokenSecret']}})


        # pprint(response.json())
        return response.json()

    def CompleteTask(self, task_title):

        try:
            self.session.post(f"https://api.gm.io/ygpz/claim-exp/{task_title}", json={},
                              headers={"Content-Type":"application/json"})
        except:
            time.sleep(2)
            try:
                self.session.post(f"https://api.gm.io/ygpz/claim-exp/{task_title}", json={},
                                  headers={"Content-Type":"application/json"})
            except:
                time.sleep(2)
                try:
                    self.session.post(f"https://api.gm.io/ygpz/claim-exp/{task_title}", json={},
                                      headers={"Content-Type":"application/json"})
                except:
                    time.sleep(2)
                    self.session.post(f"https://api.gm.io/ygpz/claim-exp/{task_title}", json={},
                                      headers={"Content-Type":"application/json"})

    def AcceptInvite(self, code):
        a = self.session.post("https://api.gm.io/ygpz/enter-referral-code", json={"code": code})

        # print(a.text, 1)
        if "Code not found or already used" in a.text:
            return False

        res = self.session.post("https://api.gm.io/ygpz/generate-codes", json={})

        return True

    def refreshToken(self, refresh_token):
        res = self.session.post("https://securetoken.googleapis.com/v1/token?key=AIzaSyBPmETcQFfpDrw_eB6s8DCkDpYYBt3e8Wg",
                          data={"grant_type": "refresh_token",
                                "refresh_token": refresh_token},
                          headers={"X-Client-Data": "CJjeygE=",
                                   "Content-Type": "application/x-www-form-urlencoded"})

        self.session.headers.update({"Authorization": res.json()['access_token']})

    def get_cf_clearance(self, response):
        site_key = "0x4AAAAAAADnPIDROrmt1Wwj"
        action = "managed"
        cData = "840ba80c69256ed3"
        chlPageData = "3gAFo2l2Mbh6anBTbXVvcHlXZElJcVlJQW95OUtRPT2jaXYyuDBBRkxncW9sdkt5YlhSWDBQUVRqdFE9PaFk2gEATzRMcWd5MkRsMDQ5ZWk2WVZpQVZwbUJFMGlvOExHem1CWTNSOVRqeEs1RnZwNXZFdVRaT3lDWTlRaHJnUmtLVmtyMkZoVUxmcXhjVGU5dElkUzgwL1ZqNTJVTTZiR3FTQnk5YnhBSHY5RnFoZlV4SW9aVm01blZVUkhxZndaS1p2Rlo5UzZqSUx6UktlYmNGb21sWkVicnNrK1lJanlzVDg3MlBFVFhYNjhtcDVXTjljNUpDOHVIKzFWTjVzNE5INTdJY3p5eE1XS2RnTGxDVFFBb3o0ajBDWElIamcyMWdNaVY4U2NHRUFLTHQzdnBEbSsyQVBUV2RiN3lGTmlLSKFt2Sw2aHNPUFBrVHovdXh4N0FmN3JyY3dRWVhiRHRBSUs1QkJaZUVrVVJaWXhJPaF0tE1UY3dORFExTnpBeU9TNDFOVGc9"
        url = "https://api.gm.io/ygpz/me"

        if '<head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0' in response.text:
            return True

        html_base64_encoded = base64.b64encode(response.text.encode('utf-8')).decode('utf-8')

        # print(html_base64_encoded)
        proxy_url = self.proxy['http']
        parsed = urlparse(proxy_url)

        proxy_ip = parsed.hostname
        proxy_port = parsed.port
        proxy_log, proxy_pass = parsed.username, parsed.password

        json = {
            "clientKey": self.cap_key,
            "task": {
                "type": "TurnstileTask",
                "websiteURL": url,
                "websiteKey": site_key,
                "proxyType": "http",
                "proxyAddress": proxy_ip,
                "proxyPort": proxy_port,
                "proxyLogin": proxy_log,
                "proxyPassword": proxy_pass,
                "cloudflareTaskType": "cf_clearance",
                "htmlPageBase64": html_base64_encoded,
                "userAgent": self.ua,
                "pageAction": action,
                "data": cData,
                "pageData": chlPageData
            }
        }

        # pprint(json)
        tries = 0
        while tries < 2:

            tries+=1

            with requests.post("https://api.capmonster.cloud/createTask", json=json, timeout=60) as response:
                # print(response.text)
                # print(response.json())
                taskId = response.json()['taskId']
                # print(taskId)

            time.sleep(5)

            json1 = {
                "clientKey": self.cap_key,
                "taskId": taskId
            }

            res = False

            tries2 = 0
            while tries2 < 40:
                with requests.post("https://api.capmonster.cloud/getTaskResult/", json=json1, timeout=60) as response:
                    result = response.json()
                    # print(response.text)
                    # print(result)

                    if result['errorId'] == 0 and result['status'] == "ready":
                        # self.logger.info(f"Result: {result}")
                        self.cf_clearance = result['solution']['cf_clearance']
                        res = True
                        break

                    elif result['errorId'] != 0:
                        # print(response.text)
                        break

                    else:
                        # print(response.text)
                        ...
                    # Wait for 3 seconds before sending the next request
                    time.sleep(5)

            if res == True:
                break
            else:
                raise Exception("Не удалось решить капчу 1")
        # print('True, 111')

        # print(self.cf_clearance)

        self.session.cookies.update({
            'cf_clearance': self.cf_clearance,
        })

        return True


    @property
    def AccountData(self) -> dict:


        tries = 0

        while tries < 2:
            result = self.session.get("https://api.gm.io/ygpz/me",
                                      headers={
                                          "Sec-Ch-Ua": 'Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                                          "Sec-Ch-Ua-Mobile": "?0",
                                          "Sec-Ch-Ua-Platform": '"Windows"',
                                          "Referer": "https://well3.com/"})

            # print(result.text)
            if '<!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>' in result.text:

                try:
                    h = self.get_cf_clearance(response=result)
                except:
                    tries+=1
                    continue



                if h:
                    result = self.session.get("https://api.gm.io/ygpz/me",
                                              headers={
                                                  "Sec-Ch-Ua": 'Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                                                  "Sec-Ch-Ua-Mobile": "?0",
                                                  "Sec-Ch-Ua-Platform": '"Windows"',
                                                  "Referer": "https://well3.com/"})
                    break
            else:
                break

        else:
            raise Exception("Captcha Solving Error")


        return result.json()


    def CompleteBreath(self):

        try:
            res = self.session.post(f"https://api.gm.io/ygpz/complete-breath-session", headers={"content-type": None})
            # print(res.json())
        except:
            time.sleep(2)
            try:
                self.session.post(f"https://api.gm.io/ygpz/complete-breath-session", headers={"content-type": None})
            except:
                time.sleep(2)
                try:
                    self.session.post(f"https://api.gm.io/ygpz/complete-breath-session", headers={"content-type": None})
                except:
                    time.sleep(2)
                    self.session.post(f"https://api.gm.io/ygpz/complete-breath-session", headers={"content-type": None})



    def _make_scraper(self):
        return tls_client.Session(client_identifier="chrome_120")


def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))


def distributor(list_, thread_number, invite_codes, cap_key):

    # print(invite_codes)
    # time.sleep(100000000)

    logger = MultiThreadLogger(thread_number)

    if mode != "tasks":


        for account in list_:

            # print(invite_codes)

            try:

                while True:

                    refCode = invite_codes[0]

                    refCodes, p = function(tw_auth_token=account['twitter']['auth_token'],
                            tw_csrf=account['twitter']['ct0'],
                            proxy=account['proxy'],
                            Ref=True,

                            logger=logger,
                            InviteCode=refCode,
                                           cap_key = cap_key)

                    if refCode == "Again":
                        logger.info("Проблема с Invite кодом, пробую следующий")
                        invite_codes = invite_codes[1:]
                        continue

                    for j in refCodes:
                        invite_codes.append(j)

                    logger.success(f"Аккаунт успешно зарегистрирован | {refCode} | {account['twitter']['auth_token']}")

                    invite_codes = invite_codes[1:]
                    logger.skip()

                    break

                # input("готово")

            except Exception as e:
                # traceback.print_exc()
                logger.error(f"Регистрация аккаунта не удалась | {str(e)}")
                logger.skip()

            time.sleep(random.randint(account['delay'][0], account['delay'][0]))

        print("Неиспользованные коды с потока {}: {}".format(thread_number, invite_codes))

    else:

        for account in list_:

            # logger.info("Регистрация пачки началась")

            try:

                function(tw_auth_token=account['twitter']['auth_token'],
                         tw_csrf=account['twitter']['ct0'],
                         proxy=account['proxy'],
                         Ref=False,

                         logger=logger,
                         InviteCode="",
                         refreshToken=account['refresh_token'],
                         cap_key=cap_key)

                logger.success(f"Аккаунт успешно сделал задания | {account['twitter']['auth_token']}")

                logger.skip()


            except Exception as e:
                logger.error(f"Не удалось выполнить задания | {str(e)}")

            time.sleep(random.randint(account['delay'][0], account['delay'][0]))




def function(proxy: str, tw_auth_token: str, tw_csrf: str , Ref: bool, logger: MultiThreadLogger,cap_key: str, InviteCode: str = None, refreshToken: str = None):



    Acc = YOGA(proxy=proxy,
                tw_csrf=tw_csrf.rstrip(),
                tw_auth_token=tw_auth_token,
                code=InviteCode,
                cap_key=cap_key)

    if refreshToken:

        main_data = Acc.refreshToken(refreshToken)

    else:


        try:
            main_data = Acc.login()
            # print(main_data)

        except:

            # traceback.print_exc()

            time.sleep(2)
            try:
                main_data = Acc.login()
            except:
                time.sleep(2)
                main_data = Acc.login()

        with open("Result.txt", "a+") as file:
            file.write(f"{main_data['refreshToken']}|{proxy}|{tw_auth_token}|{tw_csrf}\n")

        if Ref:

            try:
                res = Acc.AcceptInvite(InviteCode)
                if res:
                    logger.success(f"{tw_auth_token} | Success Invite")
                else:
                    return "Again", "Again"
            except:
                logger.success(f"{tw_auth_token} | Error Invite")

    info = Acc.AccountData

    for name, value in info['ygpzQuesting']['info']['dailyProgress'].items():

        if "complete-breath-session" in name and value['value'] != 2:
            if value['nextAvailableFrom']:
                if value['nextAvailableFrom'] < int(str(datetime.datetime.now().timestamp()).replace(".","")[:-3]):
                    try:
                        Acc.CompleteBreath()

                        logger.success(f"{tw_auth_token} | Success {name}")

                    except:
                        logger.success(f"{tw_auth_token} | Error {name}")
            else:
                try:
                    Acc.CompleteBreath()

                    logger.success(f"{tw_auth_token} | Success {name}")

                except:
                    logger.success(f"{tw_auth_token} | Error {name}")

        else:

            try:

                time.sleep(2)

                Acc.CompleteTask(name)
                logger.success(f"{tw_auth_token} | Success {name}")
            except:
                logger.error(f"{tw_auth_token} | Like/Retweet Error {name}")


    for name, value in info['ygpzQuesting']['info']['specialProgress'].items():

        if not value['expClaimed']:

            try:

                time.sleep(2)

                Acc.CompleteTask(name)
                logger.success(f"{tw_auth_token} | Success {name}")
            except:
                logger.error(f"{tw_auth_token} | Like/Retweet Error {name}")

            continue

    ref_codes = [code_data['code'] for code_data in info['referralInfo']['myReferralCodes']]


    res = Acc.AccountData
    logger.info(f"points - {res['ygpzQuesting']['info']['exp']} | rank - {res['ygpzQuesting']['info']['rank']}")

    return ref_codes, main_data



if __name__ == '__main__':

    # print('asdawdawd')
    authTokens = []
    csrfs = []
    proxies = []


    with open('Files/Proxy.txt', 'r') as file:
        for i in file:
            proxies.append(i.rstrip())

    with open('Files/Twitters.txt', 'r') as file:
        for i in file:
            authTokens.append(i.rstrip().split('auth_token=')[-1].split(';')[0])
            csrfs.append(i.rstrip().split('ct0=')[-1].split(';')[0])

    with open("utils/config.json") as file:
        data = json.loads(file.read())

    mode = data['config']['mode']

    if mode == "tasks":
        ready_array = []
        with open('Result.txt', 'r') as file:
            for i in file:
                ready_array.append({"proxy": i.split("|")[1],
                                    "twitter": {"auth_token": i.split("|")[2],
                                                "ct0": i.split("|")[3]},
                                    "refresh_token": i.split("|")[0],
                                    "delay": [data['config']['taskDelay'][0], data['config']['taskDelay'][1]],
                                    "mode": data['config']['mode']})


    else:

        ready_array = []
        for index, item in enumerate(proxies):
            ready_array.append({"proxy": item,
                                "twitter": {"auth_token": authTokens[index],
                                            "ct0": csrfs[index] if csrfs[index] != authTokens[index] else generate_csrf_token()},
                                "delay": [data['config']['taskDelay'][0], data['config']['taskDelay'][1]],
                                "mode": data['config']['mode']})

    threads_count = data['config']['threads_count']

    # print(ready_array[0])
    ready_array = split_list(ready_array, threads_count)
    if data['config']['mode'] != "tasks" and threads_count > len(data['config']['invite_codes']):
        input("Кол-во инвайт кодов меньше кол-ва потоков, регистрация невозможна")
        exit(1)

    print("Софт начал работу, прогресс выполнения можно смотреть в папке LogMT в соответствующих номерам потоков текстовиках")

    rr = list(split_list(data['config']['invite_codes'], threads_count))
    # input(rr)

    threads = []
    for index, i in enumerate(ready_array):
        thread = Thread(target=distributor,
                        args=(i,index, rr[index], data['config']['capmonster_key']))
        threads.append(thread)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    input("Софт успешно прогнал вашу пачку")


