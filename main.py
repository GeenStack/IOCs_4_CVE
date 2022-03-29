from db_module import *
from get_iocs import *


if __name__ == '__main__':
    cve_list = get_cve_list()
    for cve in cve_list:
        result = get_iocs(cve[0])
        if result:
            report = result[0]