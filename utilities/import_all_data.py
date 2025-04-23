import requests
import time
import json

# Set the base URL and headers
base_url = 'http://127.0.0.1:8005/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

# Data for the CVE update
cve_data = {
    "last_modified_earliest": "2024-09-26",
    "last_modified_latest": "2024-09-26"
}

# Function to initiate the CVE update
def initiate_cve_update():
    print(f"Initiating CVE update with data: {json.dumps(cve_data, indent=2)}")
    response = requests.post(f'{base_url}/cve/', headers=headers, json=cve_data)
    
    if response.status_code == 201:
        print("CVE update initiated successfully.")
        return response.json()['id']
    else:
        print(f"Failed to initiate CVE update: {response.status_code} - {response.text}")
        return None

# Function to check the job status
def check_job_status(job_id):
    job_url = f'{base_url}/jobs/{job_id}/'
    print(f"Checking job status for job ID: {job_id}")
    response = requests.get(job_url, headers=headers)
    if response.status_code == 200:
        job_status = response.json()
        print(f"Job status response: {json.dumps(job_status, indent=2)}")
        return job_status
    else:
        print(f"Failed to check job status: {response.status_code} - {response.text}")
        return None

# Function to monitor the jobs in sequence
def monitor_jobs():
    # Step 1: CVE update
    job_id = initiate_cve_update()
    if not job_id:
        return
    monitor_job_status(job_id, "CVE")

# Function to monitor a single job status
def monitor_job_status(job_id, job_name):
    print(f"{job_name} job initiated with ID: {job_id}")
    while True:
        job_status = check_job_status(job_id)
        if job_status:
            state = job_status['state']
            if state in ['pending', 'processing']:
                print(f"{job_name} job still {state}. Retrying in 10 seconds...")
                time.sleep(10)
            else:
                print(f"{job_name} job completed with state: {state}")
                print(f"Full response: {json.dumps(job_status, indent=2)}")
                break
        else:
            print(f"Failed to retrieve {job_name} job status, stopping monitoring.")
            break

# Run the script
if __name__ == "__main__":
    monitor_jobs()
