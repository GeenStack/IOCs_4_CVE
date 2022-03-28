import requests
from db_module import *

alien_vault_url = "https://otx.alienvault.com/api/v1/"


def get_iocs(cve_id):

    r = requests.get(alien_vault_url+"/indicators/cve/{}".format(cve_id))
    data = r.json()
    indicators = []
    indicators_id = []
    indicators_types = {}
    pulses = data["pulse_info"]["pulses"]
    if pulses:
        for pulse in pulses:
            try:
                r = requests.get(alien_vault_url+"/pulses/{}".format(pulse["id"]))
                data = r.json()
                pulse_indicators = data["indicators"]
                if pulse_indicators:
                    for indicator in pulse_indicators:
                        if indicator["type"] != "CVE":

                            if not check_ioc_in_db(cve_id, indicator["id"]):
                                query = "INSERT INTO iocs_for_cve VALUES (NULL, '{}', '{}', '{}', '{}', '{}')"

                                query = query.format(cve_id, indicator["id"], indicator["type"], indicator["indicator"], indicator["content"])
                                insert_query(query)
                                indicators.append({"alien_vault_indicator_id":indicator["id"],
                                                   "indicator":indicator["indicator"],
                                                   "type":indicator["type"],
                                                   "content":indicator["content"]})
                                indicators_id.append(indicator["id"])

                                if indicator["type"] not in indicators_types:
                                    indicators_types.update({"{}".format(indicator["type"]):1})
                                else:
                                    indicators_types[indicator["type"]] += 1
                        else:
                            pass
            except Exception as e:
                print(query)
                continue

        #Доработать отчет.
        #Создавать файл репорта в JSON, который потом и будет отправляться
        #И что делать, если отчет пустой - не возвращать репорт
        #
        #
        #
        report = "Найдены новые IOCs, связанные с {}\n".format(cve_id)
        for indicators_type in indicators_types:
            report += "{} - {}\n".format(indicators_type, str(indicators_types[indicators_type]))
        print(report)
        return {"indicators":indicators, "id_list":indicators_id, "types_count":indicators_types}
    else:
            return False