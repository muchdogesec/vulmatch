import argparse
import subprocess
import os
import traceback
import requests
import time
import calendar
from datetime import datetime, timedelta
from stix2arango.stix2arango.stix2arango import Stix2Arango
from manager import VersionManager
from pathlib import Path
from dotenv import load_dotenv
import sys
sys.path.append(Path(__file__).parent.parent)

from vulmatch.worker.utils import add_cvss_score_to_cve_object

load_dotenv()

manager = VersionManager('utility_fails.db', 'cve_fails')
MAX_RETRIES = 7
# Calculate the latest full year, month, and day
yesterday = datetime.now() - timedelta(days=1)
latest_year = yesterday.year
latest_month = yesterday.month
latest_day = yesterday.day

print(f"Latest full year: {latest_year}, Latest full month: {latest_month}, Latest full day: {latest_day}")

# List of CVE files with daily file names
all_versions = []
for year in range(1988, latest_year + 1):
    start_month = 1
    end_month = 12 if year < latest_year else latest_month
    for month in range(start_month, end_month + 1):
        days_in_month = calendar.monthrange(year, month)[1]
        if year == latest_year and month == latest_month:
            days_in_month = latest_day
        for day in range(1, days_in_month + 1):
            start_date = f"{year}_{str(month).zfill(2)}_{str(day).zfill(2)}"
            version = f"{start_date}-00_00_00-{start_date}-23_59_59"
            all_versions.append((year, month, day, version))

def parse_arguments():
    parser = argparse.ArgumentParser(description="Process NVD CVE versions.")
    parser.add_argument('--min_date', type=str, help='Start date in yyyy-mm-dd format.')
    parser.add_argument('--max_date', type=str, help='End date in yyyy-mm-dd format.')
    parser.add_argument('--ignore_embedded_relationships', action='store_true', help='Flag to ignore embedded relationships. Default is false.')
    parser.add_argument('--database', type=str, default="cti_knowledge_base_store", help='Name of the database to use. Default is "cti_knowledge_base_store".')
    parser.add_argument('--start_over', action='store_true', help='Delete database holding previous attempts.')
    return parser.parse_args()

def filter_versions_by_date(min_date, max_date):
    min_dt = datetime.strptime(min_date, "%Y-%m-%d")
    max_dt = datetime.strptime(max_date, "%Y-%m-%d")
    return [item for item in all_versions if min_dt <= datetime(item[0], item[1], item[2]) <= max_dt]

def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"Created directory: {path}")

def download_file(url, destination):
    response = requests.get(url)
    if response.status_code == 200:
        with open(destination, 'wb') as file:
            file.write(response.content)
        print(f"Downloaded file: {destination}")
        return True
    else:
        print(f"Failed to download {url} - Status Code: {response.status_code}")
        return False

def run_command(command, root_path, ignore_embedded_relationships):
    file_path = command["file"]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return True
    try:
        print(f"Inserting {file_path} into database {command['database']}...")
        s2a = Stix2Arango(database=command["database"], collection=command["collection"], file=file_path, ignore_embedded_relationships=ignore_embedded_relationships, is_large_file=True, skip_default_indexes=True)
        s2a.add_object_alter_fn(add_cvss_score_to_cve_object)
        s2a.run()
        manager.set_failed(command['version'], failed=False, reason="uploaded to arango")
        print(f"Successfully inserted {command['version']} into database.")
        return True
    except Exception as e:
        print(f"Failed to process {file_path}: {e}")
        manager.set_failed(command['version'], failed=True, reason=str(e))
        return False

def main():
    args = parse_arguments()
    print(f"Database to be used: {args.database}")

    if args.min_date and args.max_date:
        versions = filter_versions_by_date(args.min_date, args.max_date)
    elif args.min_date or args.max_date:
        print("Both --min_date and --max_date must be provided.")
        return
    else:
        versions = all_versions  # If no filter is applied, process all versions.

    if args.start_over:
        print("Recreating database tables...")
        manager.recreate_table()

    new_versions = []
    failed_map = manager.get_versions()
    for item in versions:
        year, month, day, version = item
        if failed_map.get(version) in [True, None]:
            new_versions.append(item)

    print("Will skip previously successful uploads")
    print(f"Only {len(new_versions)} of {len(versions)} items will be processed")
    versions = new_versions

    ignore_embedded_relationships = args.ignore_embedded_relationships
    database = args.database
    
    script_path = os.path.dirname(os.path.abspath(__file__))
    root_path = os.path.abspath(os.path.join(script_path, "../.."))
    
    base_url = "https://cve2stix.vulmatch.com/"
    download_errors = []
    commands = []

    for item in versions:
        year, month, day, version = item
        download_url = f"{base_url}{year}-{str(month).zfill(2)}/cve-bundle-{version}.json"
        destination_path = os.path.join(root_path, "cti_knowledge_base_store", f"nvd-cve/{year}-{str(month).zfill(2)}", f"cve-bundle-{version}.json")

        create_directory(Path(destination_path).parent)
        print(f"Processing: {download_url} -> {destination_path}")
        
        if not os.path.exists(destination_path):
            if not download_file(download_url, destination_path):
                download_errors.append(destination_path)
                continue
        
        commands.append(dict(version=version, collection='nvd_cve', database=database, file=destination_path))

    for command in commands:
        print(f"Running command for version: {command['version']}")
        attempts = 0
        while attempts < MAX_RETRIES:
            try:
                success = run_command(command, root_path, ignore_embedded_relationships)
                if success:
                    break
            except Exception as e:
                print(f"Attempt {attempts+1} failed for {command['version']}: {e}")
            attempts += 1
        if attempts == MAX_RETRIES:
            print(f"upload failed after {attempts} retries, exiting...")
            exit(12)

    if download_errors:
        print("\nDownload Errors:")
        for error in download_errors:
            print(error)

if __name__ == "__main__":
    main()