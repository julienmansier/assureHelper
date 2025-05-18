from flask import Flask, request, jsonify
import json, re

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'txt'}
cve_pattern = r'\[ CVSS:v([23]) \] \[([HCMLI])\] (\d+\.\d+) / (CVE-\d+-\d+)'
exploitable_pattern = r'Exploitable:\s+(.*)'
description_pattern = r"Description:\s+(.*?)(?:Detections|Suppressed|Current date|$)"
codePattern = r'\[\s*(BH\d+)\s*\]'
catPattern = r':\s*([^/]+)'
behPattern = r'\].*?\n\s+(.+)'
expPattern = r'Explained:(.*?)Prevalence'

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

# Process the Malware report from Assure -. converts to JSON
def processMal(content):
    entries = re.split(r'-{80,}', content)
    json_data = []

    for entry in entries:
        temp = {}

        if entry.strip():
            temp["malware_name"] = re.search(r"\[ SEVERITY:10/10 \] (.+)", entry).group(1).strip()
            
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

    
   # for item in temp:
       # print(item)

    return result




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

if __name__ == '__main__':
    app.run(debug=True, port=5001)
