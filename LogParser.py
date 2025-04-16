import os
import re
import json
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

# === REPLACE WITH YOUR DCR DETAILS ===
endpoint_uri = "https://dce-syslogforwarder-2353.uksouth-1.ingest.monitor.azure.com"
dcr_immutableid = "dcr-96f04fd38f30484faf13a6b81ae87b1d"
stream_name = "Custom-CheckpointLogs_CL"
LOG_FILE_PATH = "/var/log/syslog" 

# === Store last processed log position ===
STATE_DIR = os.path.expanduser("~/.log_forwarder/")
STATE_FILE = os.path.join(STATE_DIR, "last_log_position.txt")

# Ensure state directory exists
os.makedirs(STATE_DIR, exist_ok=True)

# === Helpers ===
def split_log_entries(raw_log):
    """Split raw log file into individual Check Point log entries."""
    return re.findall(r'<\d+>1 \d{4}-\d{2}-\d{2}T.*?(?=<\d+>1 |\Z)', raw_log, flags=re.DOTALL)

def extract_key_value_pairs(log_text):
    return dict(re.findall(r'(\w+):"([^"]*?)"', log_text))

def parse_log_line(log_line):
    header_match = re.match(r'^<\d+>1 (\S+) (\S+) (\S+) (\d+) - \[?', log_line)
    if not header_match:
        return None, None

    timestamp_str = header_match.group(1)
    try:
        log_time = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        log_time = datetime.now(timezone.utc)

    body = log_line[header_match.end():]
    kv_data = extract_key_value_pairs(body)

    def safe_get(key, default=""): return kv_data.get(key, default)

    return {
        "TimeGenerated": log_time.isoformat(),
        "Action": safe_get("action"),
        "ConnectionDirection": safe_get("conn_direction"),
        "Flags": safe_get("flags"),
        "InterfaceDirection": safe_get("ifdir"),
        "InterfaceName": safe_get("ifname"),
        "LogId": safe_get("logid"),
        "LogUID": safe_get("loguid"),
        "OriginIP": safe_get("origin"),
        "OriginSicName": safe_get("originsicname"),
        "SequenceNumber": safe_get("sequencenum"),
        "LogTimeEpoch": safe_get("time"),
        "Version": safe_get("version"),
        "PolicyIdTag": safe_get("__policy_id_tag"),
        "DestinationIP": safe_get("dst"),
        "LastUpdateTime": "",
        "LogDelay": safe_get("log_delay"),
        "PolicyLayerName": safe_get("layer_name"),
        "PolicyLayerUUID": safe_get("layer_uuid"),
        "MatchID": safe_get("match_id"),
        "ParentRule": safe_get("parent_rule"),
        "RuleAction": safe_get("rule_action"),
        "RuleName": safe_get("rule_name"),
        "RuleUID": safe_get("rule_uid"),
        "NatAdditionalRuleNum": safe_get("nat_addtnl_rulenum"),
        "NatRuleUID": safe_get("nat_rule_uid"),
        "NatRuleNum": safe_get("nat_rulenum"),
        "Product": safe_get("product"),
        "Protocol": safe_get("proto"),
        "SourcePort": int(safe_get("s_port", "0")),
        "ServiceName": safe_get("service"),
        "ServiceID": safe_get("service_id"),
        "SourceIP": safe_get("src"),
        "TranslatedPort": int(safe_get("xlatesport", "0")),
        "TranslatedDestinationIP": safe_get("xlatedst"),
        "TranslatedSourcePort": int(safe_get("xlatesport", "0")),
        "TranslatedSourceIP": safe_get("xlatesrc"),
        "InZone": safe_get("inzone"),
        "OutZone": safe_get("outzone"),
        "RawLogMessage": log_line.strip()
    }, log_time

# === Read last processed position ===
last_position = 0
if os.path.exists(STATE_FILE):
    with open(STATE_FILE, "r") as f:
        last_position = int(f.read().strip() or 0)

# === Verify log file exists before processing ===
if not os.path.exists(LOG_FILE_PATH):
    print(f"⚠️ Log file {LOG_FILE_PATH} not found. Resetting log position.")
    last_position = 0

log_entries = []
current_position = last_position

# === Read new logs from last position ===
try:
    with open(LOG_FILE_PATH, "r", encoding="utf-8") as file:
        file_size = os.stat(LOG_FILE_PATH).st_size
        if last_position > file_size:
            print("⚠️ Log file rotated. Resetting last position.")
            last_position = 0

        file.seek(last_position)
        raw_log_data = file.read()
        logs = split_log_entries(raw_log_data)

        for log_line in logs:
            parsed_log, log_time = parse_log_line(log_line)
            if parsed_log:
                log_entries.append((parsed_log, log_time))

        current_position = file.tell()

except PermissionError:
    print(f"❌ ERROR: No permission to read '{LOG_FILE_PATH}'. Try running with sudo.")
    exit(1)

# === Authenticate with Azure ===
credential = DefaultAzureCredential()
client = LogsIngestionClient(endpoint=endpoint_uri, credential=credential, logging_enable=True)

# === Upload logs in 30-minute batches ===
if log_entries:
    log_entries.sort(key=lambda x: x[1])
    batch = []
    batch_start_time = log_entries[0][1]

    for log, log_time in log_entries:
        if (log_time - batch_start_time) > timedelta(minutes=30):
            try:
                client.upload(rule_id=dcr_immutableid, stream_name=stream_name, logs=[log for log, _ in batch])
                print(f"✅ Uploaded {len(batch)} log entries from {batch_start_time} to {log_time} UTC")
            except HttpResponseError as e:
                print(f"❌ Upload failed for batch: {e}")
            batch = []
            batch_start_time = log_time

        batch.append((log, log_time))

    if batch:
        try:
            client.upload(rule_id=dcr_immutableid, stream_name=stream_name, logs=[log for log, _ in batch])
            print(f"✅ Uploaded {len(batch)} log entries from {batch_start_time} to {log_entries[-1][1]} UTC")
        except HttpResponseError as e:
            print(f"❌ Upload failed for last batch: {e}")

    with open(STATE_FILE, "w") as f:
        f.write(str(current_position))
else:
    print("⚠️ No new logs found.")

