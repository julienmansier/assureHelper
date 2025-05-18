# assureHelper
Helper API that converts the output from the Assure CLI into JSON

## This helper API has three endpoints for various Assure CLI reports. These endpoints are for:
1) Malware
2) Vulnerabilities 
3) Behaviors

## The endpoits support only POST and require a file with the request. Only a '.txt' file extension is supported. The the reponse from the API is a JSON version of the text file. 

## Default Settings:
1) Creates endpoints are 127.0.0.1
2) Listens on port 5001

#### Examples
```
curl -F "file=@test_file.txt" http://127.0.0.1:5001/mal 
```