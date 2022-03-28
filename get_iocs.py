import requests


alien_vault_url = "https://otx.alienvault.com/api/v1/"


def get_iocs(cve_id):
    r = requests.get(alien_vault_url+"/indicators/cve/{}".format(cve_id))
    data = r.json()
    indicators = []
    indicators_id = []
    pulses = data["pulse_info"]["pulses"]
    if pulses:
        for pulse in pulses:
            r = requests.get(alien_vault_url+"/pulses/{}".format(pulse["id"]))
            data = r.json()
            pulse_indicators = data["indicators"]
            if pulse_indicators:
                for indicator in pulse_indicators:
                    if indicator["id"] not in indicators_id:
                        indicators.append({"alien_vault_indicator_id":indicator["id"],
                                           "indicator":indicator["indicator"],
                                           "type":indicator["type"],
                                           "content":indicator["content"]})
                        indicators_id.append(indicator["id"])
        return {"indicators":indicators, "id_list":indicators_id}
    else:
        return False