# assureHelper
Helper API that converts the output from the Assure CLI into JSON. It also will filter all of the JSON reports into a single JSON report based on configurable input. For example, only give me actual (not suspected) malware, vulns above 6.5, and these three behaviors: BH10101, BH10102, BH101013, etc.

## This helper API has three endpoints for various Assure CLI reports. These endpoints are for:
1) Malware
2) Vulnerabilities 
3) Behaviors
4) Threats
5) Filtering

## The endpoits support only POST and require a file with the request. Only a '.txt' file extension is supported. The the reponse from the API is a JSON version of the text file. 

## Default Settings:
1) Creates endpoints are 127.0.0.1
2) Listens on port 80 (HTTP)

#### Examples
```
curl -F "file=@test_file.txt" http://127.0.0.1/mal > mal.json
curl -F "file=@test_file.txt" http://127.0.0.1/vuln > vulns.json
curl -F "file=@test_file.txt" http://127.0.0.1/bh > bh.json
curl -F "file=@test_file.txt" http://127.0.0.1/th > th.json
curl -F "config=@config.json" -F "malware=@mal.json" -F "vulns=@vulns.json" -F "behavior=@bh.json" http://127.0.0.1/process > filtered.json
```