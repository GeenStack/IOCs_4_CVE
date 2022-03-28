import requests
from db_module import *

alien_vault_url = "https://otx.alienvault.com/api/v1/"


def get_iocs(cve_id):

    r = requests.get(alien_vault_url+"/indicators/cve/{}".format(cve_id))
    data = r.json()
    indicators = []
    indicators_id = []
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
                        else:
                            pass
            except Exception as e:
                print(query)
                continue

        return {"indicators":indicators, "id_list":indicators_id}
    else:
            return False