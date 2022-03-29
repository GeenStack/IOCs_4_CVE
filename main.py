from db_module import *
from get_iocs import *
from datetime import datetime
import requests


def get_time():
    current_time = datetime.now()
    current_time = current_time.strftime("%d-%m-%Y %H:%M")
    return current_time


def alert(report):
    current_time = get_time()
    message = "{}\n{}".format(current_time, report)
    for chat in CHATS:
        r = requests.get(API_URL + "sendMessage?chat_id={}&text={}".format(str(chat), message))



if __name__ == '__main__':
    cve_list = get_cve_list()
    for cve in cve_list:
        result = get_iocs(cve[0])
        if result:
            report = result[0]
            alert(report)