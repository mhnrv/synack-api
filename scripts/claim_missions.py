#!/usr/bin/env python3

import time
import synack

h = synack.Handler(login=True)
h.alerts.discord("INFO", f"bot started by binarysouljour")

known_missions = 0

while True:
    time.sleep(10)
    print("polling for missions...")
    curr_missions = h.missions.get_count()
    if curr_missions and curr_missions > known_missions:
        h.alerts.discord("INFO", f"There are {curr_missions} mission(s)")
        known_missions = curr_missions
        missions = h.missions.get_available()
        print(f"I grabbed a list of {len(missions)} missions!")
        for m in missions:
            h.alerts.discord("WARN", f"Attempting to claim mission : {m['title']} for ${m['payout']['amount']}")
            time.sleep(0.5)
            outcome = h.missions.set_claimed(m)
            if outcome["sucess"]:
                h.alerts.discord("INFO", f"Successfully claimed mission : {m['title']} for ${m['payout']['amount']}")
            else:
                h.alerts.discord("ERROR", f"Failed to claim mission : {m['title']} for ${m['payout']['amount']}")
    elif curr_missions == 0:
        known_missions = 0
