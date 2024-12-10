import requests
import time
import json

# Set the base URL and headers
base_url = 'http://127.0.0.1:8005/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Modes for arango-cti-processor
arango_modes = [
    "cve-cwe",
    "cve-capec",
    "cve-attack",    
    "cve-epss",
    "cve-kev"
]

# Function to initiate the CVE update
def initiate_cve_update():
    cve_data = {
        "last_modified_earliest": "2024-09-01",
        "last_modified_latest": "2024-09-30"
    }
    print(f"Initiating CVE update with data: {json.dumps(cve_data, indent=2)}")
    response = requests.post(f'{base_url}/cve/', headers=headers, json=cve_data)
    
    if response.status_code == 201:
        print("CVE update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CVE update: {response.status_code} - {response.text}")
        return None

# Function to check the job status and wait for it to complete
def check_job_status(job_id):
    job_url = f'{base_url}/jobs/{job_id}/'
    while True:
        print(f"Checking job status for job ID: {job_id}")
        response = requests.get(job_url, headers=headers)
        if response.status_code == 200:
            job_status = response.json()
            print(f"Job status response: {json.dumps(job_status, indent=2)}")
            state = job_status['state']
            
            if state == 'completed':
                print(f"Job {job_id} completed successfully.")
                return job_status
            else:
                print(f"Job {job_id} still in state: {state}. Waiting for 30 sec before retrying...")
                time.sleep(30)  # Wait for 1 minute before checking again
        else:
            print(f"Failed to check job status: {response.status_code} - {response.text}")
            break

# Function to monitor a single job status and ensure completion before proceeding
def monitor_job_status(job_id, job_name):
    print(f"{job_name} job initiated with ID: {job_id}")
    job_status = check_job_status(job_id)
    
    if job_status and job_status['state'] == 'completed':
        print(f"{job_name} job completed successfully.")
    else:
        print(f"{job_name} job did not complete successfully.")

# Function to initiate arango-cti-processor updates
def initiate_arango_cve_processor_update(mode):
    print(f"Initiating arango-cti-processor update with mode: {mode}")
    response = requests.post(f'{base_url}/arango-cti-processor/{mode}/', headers=headers)
    
    if response.status_code == 201:
        print(f"arango-cti-processor update for {mode} initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate arango-cti-processor update for {mode}: {response.status_code} - {response.text}")
        return None

# Function to monitor and initiate multiple jobs
def monitor_jobs():
    # Step 1: CVE update
    job_id = initiate_cve_update()
    if job_id:
        monitor_job_status(job_id, "CVE")

# Run the script
if __name__ == "__main__":
    monitor_jobs()
