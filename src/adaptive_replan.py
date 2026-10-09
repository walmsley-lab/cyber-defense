"""Replan from evidence without claiming unobserved chains have succeeded."""
import json
from src.campaign import ranked,validate,apply_event

def replan(campaign, observations):
    campaign=json.loads(json.dumps(campaign))
    validate(campaign)
    events=[]
    for obs in observations:
        action_id,status=obs.get("action_id"),obs.get("status")
        if status not in {"passed","failed","blocked","inconclusive"}:
            raise ValueError("Unsupported observed outcome")
        action=next((a for a in campaign["actions"] if a["id"]==action_id),None)
        if not action: raise ValueError("Unknown action")
        apply_event(campaign,{"action_id":action_id,"status":status})
        events.append({"action_id":action_id,"status":status,"evidence":obs.get("evidence")})
    next_steps=ranked(campaign)
    return {"campaign":campaign,"applied":events,"next":next_steps,
            "ready":[x for x in next_steps if x["readiness"]=="ready"],
            "blocked":[x for x in next_steps if x["readiness"]=="blocked-by-prerequisite"],
            "waiting":[x for x in next_steps if x["readiness"]=="waiting"]}
