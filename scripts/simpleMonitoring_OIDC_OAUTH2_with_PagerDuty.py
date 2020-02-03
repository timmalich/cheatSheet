#!/usr/bin/python

# requires: sudo apt install python-pip / sudo zypper in python-pip
#           pip install rauth
import json, time, requests, urllib3, datetime, traceback, argparse, socket
from rauth import OAuth2Service

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("--sso", help = "SSO url", default = "https://XXXXXXX/as/token.oauth2")
parser.add_argument("--client-id", help = "Client ID")
parser.add_argument("--client-secret", help = "The client secret")
parser.add_argument("--env", help = "The environment Dev/Int/Prod", default = "DEV")
parser.add_argument("--base-url", help = "the monitoring base url", default = "https://XXXXXXXX")
parser.add_argument("--routing-key", help = "The Pager Duty Routing Key")
parser.add_argument("--client-url", help = "Client URL for Pager Duty", default = socket.gethostname())
parser.add_argument("--client-name", help = "Client name attribute for Pager Duty", default = "OpsServer")
args = parser.parse_args()
print ("Current configuration:")
for arg in vars(args):
    print (arg, getattr(args, arg))

EXPECTED_ID="D-Country.DE"
MONITORING_ENDPOINT = "/XXXXXX/" + EXPECTED_ID

def getsession():
    print("Getting new Session for " + args.base_url)
    return OAuth2Service(
        client_id=args.client_id,
        client_secret=args.client_secret,
        access_token_url=args.sso,
        base_url=args.base_url
    ).get_auth_session(
        data =  {
            'scope':'openid',
            'grant_type':'client_credentials'
        },
        decoder = json.loads
    )

timeout=30
session = getsession()
while True:
    try:
        iso8601timestamp = datetime.datetime.now().isoformat()
        print(iso8601timestamp + " calling " + MONITORING_ENDPOINT )
        try:
            response = session.get(MONITORING_ENDPOINT, verify=False)
            actualId = response.json()['organization']['id']
        except:
            actualId = "wroooooong"
        if EXPECTED_ID != actualId:
            print("OH OH IT WENT WRONG. Alarming Pager Duty. Timeout: %d" %timeout)
            pagerDutyPayload={
              "payload": {
                "summary": args.env + " REST API MONITORING FAILED",
                "timestamp": iso8601timestamp,
                "source": socket.gethostname(),
                "severity": "error",
                "component": "restapi",
                "group": "dev",
                "custom_details": {
                  "request_url": json.dumps(response.url),
                  "status_code": response.status_code,
                  "response": json.dumps(response.content),
                  "expecting": EXPECTED_ID
                }
              },
              "routing_key": args.routing_key,
              "links": [{
                "href": args.base_url,
                "text": "GEMS " + args.env
              }],
              "event_action": "trigger",
              "client": args.client_name,
              "client_url": args.client_url
            }
            timeout+=300
            pdresponse = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                data = json.dumps(pagerDutyPayload),
                headers = {"Content-Type": "application/json"}
            )
            print(pdresponse.content)
        else:
          timeout=30
    except Exception as e:
        print("Unkown Error")
        traceback.print_exc()
    time.sleep(timeout)
