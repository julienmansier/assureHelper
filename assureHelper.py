from flask import Flask, request, jsonify
import json
import base64
import re

ALLOWED_EXTENSIONS = {'txt'}
cve_pattern = r'\[ CVSS:v([23]) \] \[([HCMLI])\] (\d+\.\d+) / (CVE-\d+-\d+)'
exploitable_pattern = r'Exploitable:\s+(.*)'
description_pattern = r"Description:\s+(.*?)(?:Detections|Suppressed|Current date|$)"
codePattern = r'\[\s*(BH\d+)\s*\]'
catPattern = r':\s*([^/]+)'
behPattern = r'\].*?\n\s+(.+)'
expPattern = r'Explained:(.*?)Prevalence'
thIDPattern = r'\[ (TH\d+) \]'
descriptionPattern = r'Detected presence of files with behaviors commonly used by malicious software\.'
rootCausePattern = r'Root Cause ---------------------------------------------------------------------.*?\[ (BH\d+) \] (.+?)\n'
detectionsPattern = r'Violations ---------------------------------------------------------------------.*?(\d+\) (.+?)\n'


app = Flask(__name__)

# Process the Malware report from Assure -. converts to JSON
def processMal(content):
    entries = re.split(r'-{80,}', content)
    json_data = []
    for entry in entries:
        temp = {}
        if entry.strip():
            match = re.search(r"\[ SEVERITY:10/10 \] (.+)", entry)
            if match:
                temp["malware_name"] = match.group(1).strip()
            else:
                # Handle the case where no match is found
                temp["malware_name"] = "No match found"  # Or some other default value or error handling
            if 'SUSPECT' in entry:
                temp["suspected_malware"] = True
            else:
                temp["suspected_malware"] = False
            temp["detections"] = re.findall(r'\d+\) (.+)', entry)
            json_data.append(temp)
    return json_data



def parse_detections(text):
    results = []
    # Does the CVE contain Detections
    if "Detections ---------------------------------------------------------------------" in text:
        detectSection = text.split("Detections ---------------------------------------------------------------------")

        # Check to see if the string split includes Suppressed content as well
        if "Suppressed ---------------------------------------------------------------------" in detectSection[1]:
            cleanDetectSection = detectSection[1].split("Suppressed ---------------------------------------------------------------------" )

            # Create a list and interate through applying the Regex
            lines = cleanDetectSection[0].splitlines()
            pattern = r'^\s*\d+\)\s*(.*)$'
            for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))
        else:
            # Create a list and interate through applying the Regex
            lines = detectSection[1].splitlines()
            pattern = r'^\s*\d+\)\s*(.*)$'
            for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))
        # Return the list 
        return results
    else:
        # No detections so return None (null)
        return None
    


def parse_suppressed(text):
    results = []
    if "Suppressed ---------------------------------------------------------------------" in text:
        suppressedSection = text.split("Suppressed ---------------------------------------------------------------------" )

        lines = suppressedSection[1].splitlines()
        pattern = r'^\s*\d+\)\s*(.*)$'
        for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))

        return results
    else:
        return None
    



def processVuln(content):
    # Initialize the result dictionary
    result = []

    # Split the input into sections
    sections = content.split('--------------------------------------------------------------------------------')

    # Parse the main section
    for i, section in enumerate(sections[1:]):
        parsed = {}
        temp = section.strip()


        # Get CVE Name
        cve_name = re.search(cve_pattern, temp).group(4)
        parsed['cve_name']= cve_name
        
        # Get CVSS Score
        cvss_score = re.search(cve_pattern, temp).group(3)
        parsed['cve_score']=float(cvss_score)

        # Get Exploitable
        exploitable = re.search(exploitable_pattern, temp)
        parsed["exploitable"] = exploitable.group(1)

        # Get Description
        description = re.search(description_pattern, temp, re.DOTALL)
        #print(description.group(1).strip().replace("\n", "").replace("\t", ""))
        description = description.group(1).strip().replace("\n", "").replace("\t", "")
        description = re.sub(r'\s+', ' ', description)
        parsed['description'] = description

        parsed['detections']=parse_detections(temp)
        parsed['suppressed']=parse_suppressed(temp)
    
        result.append(parsed)

    return result




def processBehaviors(content):
    # Initialize the result dictionary
    result = []
    temp = []

    # Split the input into sections
    sections = content.split('--------------------------------------------------------------------------------')

    # Combine the two split sections into one
    # and add to a new list
    for i in range(int(len(sections)/2)):
        temp = {}
        tempDect = []
        
        sect1 = sections[i*2+1]
        sect2 = sections[i*2+2]

        # Get BH Code
        temp["bhcode"]= re.search(codePattern, sect1).group(1)


        # Get Category
        temp["category"]= re.search(catPattern, sect1).group(1)

        # Get Behavior
        temp["behavior"] = re.search(behPattern, sect1).group(1)

        # Get Explaination 
        tempExplain = re.search(expPattern, sect2, re.DOTALL).group(1)
        temp["explaination"]= re.sub(r'\s+', ' ', tempExplain)

        # Get Detections
        if "Detections ---------------------------------------------------------------------" in sect2:
            detectSection = sect2.split("Detections ---------------------------------------------------------------------")

            lines = detectSection[1].splitlines()
            pattern = r'^\s*\d+\)\s*(.*)$'
            for line in lines:
                match = re.match(pattern, line)
                if match:
                    tempDect.append(match.group(1))

            temp["detections"] = tempDect
        else:
            temp["detections"] = []


        result.append(temp)

    
    return result


def processThreatHunting(content):
    # Initialize the result dictionary
    result = []

    # Split the input into sections
    sections = content.split('--------------------------------------------------------------------------------')

    # Parse the main section
    for section in sections[1:]:
        parsed = {}
        temp = section.strip()

        # Get thID
        thID = re.search(thIDPattern, temp).group(1)
        parsed['thID'] = thID

        # Get Description
        tempParse = temp.split('Root Cause ---------------------------------------------------------------------')
        desc = tempParse[0].split(')')[1]
        if desc:
            parsed["description"] = re.sub(r'\s+', ' ', desc.strip())


        # Get Root Cause
        #rootCause = re.search(rootCausePattern, temp, re.DOTALL)
        tempParse = temp.split('Violations ---------------------------------------------------------------------')
        tempParse = tempParse[0].split('Root Cause ---------------------------------------------------------------------')
        if tempParse[1]:
            parsed['root_cause'] = re.sub(r'\s+', ' ', tempParse[1].strip())

        # Get Detections
        detections = temp.split('Violations ---------------------------------------------------------------------')
        if detections[1]:
            parsed['detections'] = re.sub(r'\s+', ' ', detections[1].strip())

        result.append(parsed)

    return result

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def handle_file_upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File extension not allowed"}), 400

    # Read file content
    file_content = file.read()

    # Try to decode file content to string for JSON response
    try:
        content_str = file_content.decode('utf-8')
    except UnicodeDecodeError:
        # If binary or non-UTF8, return base64 encoded string instead
        import base64
        content_str = base64.b64encode(file_content).decode('utf-8')

    return content_str

## ========================================================
## SBOM filtering functions
## ========================================================

def process_config(config_content):
    global checkMalware, checkSuspect, vulnExists, vulnThreshold, behaviors, findings
    temp = {}

    try:
        data = config_content
        temp["config"]=data
        temp["findings"]=[]
        print(f"Successfully loaded Config data")

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Config file")
    except Exception as e:
        print(f"An error occurred while processing Config JSON: {str(e)}")
    
    return temp


def filter_vulns(vuln_file, findings):
    vulnThreshold = float(findings["config"]["vulnThreshold"])
    vulnExists = findings["config"]["vulnExists"]

    try:
        vuln = vuln_file
        print(f"Successfully loaded the Vulns data")

        if len(vuln) > 0:
            print("Vulnerabilities detected!")
            for item in vuln:
                temp = {}
                if item["cve_score"] > vulnThreshold and item["detections"]:
                    temp["type"]="vulnerability"
                    temp["name"]=item["cve_name"]
                    temp["severity"] = item["cve_score"]
                    temp["description"] = item["description"]
                    temp["locations"]=item["detections"]
                    findings["findings"].append(temp)
                elif vulnExists and "YES" in item["exploitable"] and item["detections"]:
                    temp["type"]="vulnerability"
                    temp["name"]=item["cve_name"]
                    temp["severity"] = item["cve_score"]
                    temp["description"] = item["description"]
                    temp["locations"]=item["detections"]
                    findings["findings"].append(temp)

            return findings
        else:
            return findings
        

        print("Done processing vulns!")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")


def filter_malware(malware_file, findings):
    checkSuspect = findings["config"]["suspect"]
    checkMalware = findings["config"]["malware"]

    try:
        mal = malware_file
        print(f"Successfully loaded the Malware data")
    
        ##Check for Malware
        if checkMalware and len(malware_file) > 0:
            print("Malware Detected!")
            
            for item in mal:
                temp = {}
                if item["malware_name"] and not item["suspected_malware"]: ## Check if malware is TRUE
                    temp["type"]="malware"
                    temp["name"]=item["malware_name"]
                    temp["suspect"] = False
                    temp["locations"]=item["detections"]
                    findings["findings"].append(temp)
                elif  checkSuspect and  item["suspected_malware"]: ## Check if config has suspect set to TRUE
                    temp["type"]="suspected malware"
                    temp["name"]=item["malware_name"]
                    temp["suspect"] = True
                    temp["locations"]=item["detections"]
                    findings["findings"].append(temp)
            return findings
        else:
            print("Not checking for malware...")
            return findings

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")


def filter_behaviors(behavior_file, findings):
    behaviors = findings["config"]["behaviors"]

    if len(behavior_file) > 0:
        for behavior in behaviors:
            temp = {}
            search = next((item for item in behavior_file if item["bhcode"] == behavior), None)

            if search is not None:
                temp["type"] = "behavior"
                temp["name"] = behavior
                temp["description"] = search["behavior"] + " => " + search["explaination"]
                temp["locations"] = search["detections"]
                findings["findings"].append(temp)
        return findings
    else:
        return findings

def get_all_files(findings):
    files = []

    for items in findings["findings"]:
        temp = items["locations"]

        for loc in temp:
            files.append(loc)
    
    findings["files"] = files
    return findings

## =========================================================
## Start of the API endpoint definitions
## =========================================================

@app.route('/ping', methods=['GET'])
def ping():
    return "pong"

@app.route('/mal', methods=['POST'])
def mal():
    content = handle_file_upload()
    if isinstance(content, tuple):  # error response
        return content
    
    if "No issues" in content:
        return {}
    else:
        jsonContent = processMal(content)
        return jsonContent

@app.route('/vuln', methods=['POST'])
def vuln():
    content = handle_file_upload()
    if isinstance(content, tuple):
        return content
    
    if "No issues" in content:
        return {}
    else:
        jsonContent = processVuln(content)
        return jsonContent

@app.route('/bh', methods=['POST'])
def bh():
    content = handle_file_upload()
    if isinstance(content, tuple):
        return content
    
    if "No issues" in content:
        return {}
    else:
        jsonContent = processBehaviors(content)
        return jsonContent


@app.route('/th', methods=['POST'])
def th():
    content = handle_file_upload()
    if isinstance(content, tuple):
        return content
    
    if "No issues" in content:
        return {}
    else:
        jsonContent = processThreatHunting(content)
        return jsonContent
    
@app.route('/process', methods=['POST'])
def process():
    findings = {}

    # Get files from the POST request
    config_file = request.files['config']
    vulns_file = request.files['vulns']
    malware_file = request.files['malware']
    behavior_file = request.files['behavior']

    # Read and parse JSON data from files
    config_content = json.load(config_file)
    vulns_content = json.load(vulns_file)
    malware_content = json.load(malware_file)
    behavior_content = json.load(behavior_file)

    # Process the files
    findings = process_config(config_content)
    findings = filter_vulns(vulns_content, findings)
    findings = filter_malware(malware_content, findings)
    findings = filter_behaviors(behavior_content, findings)
    findings = get_all_files(findings)

    # Return the findings as a JSON response
    return jsonify(findings)

if __name__ == '__main__':
    app.run(debug=False, host='172.23.24.30', port=80)
