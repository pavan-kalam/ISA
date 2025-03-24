import subprocess
import json
import os

def test_spiderfoot_cli(query):
    try:
        # Path to the SpiderFoot script (sf.py)
        spiderfoot_path = os.path.join("spiderfoot", "sf.py")  # Relative path
        
        # Debug: Print the path
        print(f"SpiderFoot path: {spiderfoot_path}")
        
        # Run SpiderFoot CLI command
        command = f"python3 {spiderfoot_path} -q {query} -o json"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            return None
        
        # Parse the JSON output
        data = json.loads(result.stdout)
        return data
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

# Test the function
query = "example.com"
data = test_spiderfoot_cli(query)
if data:
    print("SpiderFoot CLI is working!")
    print(data)
else:
    print("SpiderFoot CLI is not working.")