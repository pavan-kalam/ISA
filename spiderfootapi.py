import subprocess
import json

container_name = "spiderfoot"

# Run SpiderFoot CLI inside the container and redirect output to a file on the host
try:
    subprocess.run([
        "docker", "exec", container_name,
        "python3", "sf.py",
        "-m", "sfp_dnsresolve",
        "-s", "example.com",
        "-o", "json"
    ], stdout=open("results.json", "w"), check=True)
except subprocess.CalledProcessError as e:
    print("Failed to run SpiderFoot scan:", e)
    exit(1)

# Read the results
try:
    with open("results.json", "r") as f:
        results = json.load(f)
    print("Results:", results)
except FileNotFoundError:
    print("Results file not found. The scan may have failed.")
    exit(1)
except json.JSONDecodeError:
    print("Failed to parse results as JSON. The scan may have produced invalid output.")
    exit(1)