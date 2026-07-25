import math
import numpy as np
import pandas as pd
from collections import defaultdict

def _default_entity_profile():
    return {
        "count": 0,
        "hour_mean": None,
        "hour_std": None,
        "duration_mean": None,
        "duration_std": None,
        "cmd_len_mean": None,
        "cmd_len_std": None,
        "geo_counts": defaultdict(float),
        "resource_counts": defaultdict(float),
        "auth_counts": defaultdict(float),
        "fingerprints": set(),
        "macs": set(),
        "commands_seen": set()
    }

def _default_peer_profile():
    return {
        "count": 0,
        "hours": [],
        "durations": [],
        "cmd_lens": [],
        "geo_counts": defaultdict(float),
        "resource_counts": defaultdict(float),
        "auth_counts": defaultdict(float),
        "commands_seen": set()
    }

class EntityBaselineProfiler:
    """
    Computes and maintains statistical baseline profiles per entity (user, service_account, edge_device).
    
    Includes:
    - Trailing window profiling (login hours, locations, resources, duration, auth methods, fingerprints).
    - Peer-group fallback for cold-start entities (< N historical events).
    - Exponential decay on historical statistics so legitimate behavioral changes are absorbed over time.
    """

    def __init__(self, cold_start_threshold=5, decay_alpha=0.05):
        """
        :param cold_start_threshold: Minimum number of historical events required for entity profile.
        :param decay_alpha: Exponential decay factor (0 < alpha <= 1) for updating rolling stats.
                            Newer sessions carry weight alpha, past history carries weight (1 - alpha).
        """
        self.cold_start_threshold = cold_start_threshold
        self.decay_alpha = decay_alpha
        
        # Entity-level profiles
        self.entity_profiles = defaultdict(_default_entity_profile)

        # Peer-group profiles (aggregated by entity_type)
        self.peer_profiles = defaultdict(_default_peer_profile)

        # Geo coordinates cache
        self.geo_coords = {
            "New York, US": (40.7128, -74.0060),
            "San Francisco, US": (37.7749, -122.4194),
            "London, UK": (51.5074, -0.1278),
            "Frankfurt, DE": (50.1109, 8.6821),
            "Tokyo, JP": (35.6762, 139.6503),
            "Singapore, SG": (1.3521, 103.8198),
            "Sydney, AU": (-33.8688, 151.2093),
            "Moscow, RU": (55.7558, 37.6173),
            "Bucharest, RO": (44.4323, 26.1063)
        }

    def fit(self, df_logs):
        """
        Fits baseline profiles chronologically over historical logs.
        Applies exponential decay moving averages on numerical and categorical distributions.
        """
        print("[+] Fitting baseline profiler with exponential decay logic...")
        df_sorted = df_logs.copy()
        df_sorted["dt"] = pd.to_datetime(df_sorted["timestamp"])
        df_sorted = df_sorted.sort_values("dt")

        for idx, row in df_sorted.iterrows():
            self.update(row)

        print(f"[+] Profiler fit complete. Profiled {len(self.entity_profiles)} entities across {len(self.peer_profiles)} peer groups.")

    def update(self, row):
        """
        Updates profile statistics for an entity using Exponential Moving Averages (EMA):
        mu_t = (1 - alpha) * mu_{t-1} + alpha * x_t
        """
        eid = row["entity_id"]
        etype = row["entity_type"]
        dt = pd.to_datetime(row["timestamp"])
        hour = dt.hour + dt.minute / 60.0
        duration = float(row["session_duration"])
        geo = row["geo_location"]
        resource = row["resource_accessed"]
        auth = row["auth_method"]
        fp = row["device_fingerprint"]
        mac = fp.split(" | ")[1] if " | " in fp else "unknown"

        # Extract commands length
        cmd_len = 0.0
        try:
            cmds = eval(row["command_sequence"]) if isinstance(row["command_sequence"], str) else row["command_sequence"]
            if isinstance(cmds, list):
                cmd_len = float(len(cmds))
        except Exception:
            pass

        # Update peer group history
        peer = self.peer_profiles[etype]
        peer["count"] += 1
        peer["hours"].append(hour)
        peer["durations"].append(duration)
        peer["cmd_lens"].append(cmd_len)
        peer["geo_counts"][geo] += 1.0
        peer["resource_counts"][resource] += 1.0
        peer["auth_counts"][auth] += 1.0

        # Update entity profile with Exponential Decay
        ep = self.entity_profiles[eid]
        ep["count"] += 1
        ep["fingerprints"].add(fp)
        ep["macs"].add(mac)

        for g in list(ep["geo_counts"].keys()):
            ep["geo_counts"][g] *= (1.0 - self.decay_alpha)
        ep["geo_counts"][geo] += self.decay_alpha

        for r in list(ep["resource_counts"].keys()):
            ep["resource_counts"][r] *= (1.0 - self.decay_alpha)
        ep["resource_counts"][resource] += self.decay_alpha

        for a in list(ep["auth_counts"].keys()):
            ep["auth_counts"][a] *= (1.0 - self.decay_alpha)
        ep["auth_counts"][auth] += self.decay_alpha

        alpha = self.decay_alpha
        if ep["hour_mean"] is None:
            ep["hour_mean"] = hour
            ep["hour_std"] = 1.0
            ep["duration_mean"] = duration
            ep["duration_std"] = 10.0
            ep["cmd_len_mean"] = cmd_len
            ep["cmd_len_std"] = 1.0
        else:
            diff_h = hour - ep["hour_mean"]
            ep["hour_mean"] += alpha * diff_h
            ep["hour_std"] = math.sqrt((1 - alpha) * (ep["hour_std"]**2) + alpha * (diff_h**2))

            diff_d = duration - ep["duration_mean"]
            ep["duration_mean"] += alpha * diff_d
            ep["duration_std"] = math.sqrt((1 - alpha) * (ep["duration_std"]**2) + alpha * (diff_d**2))

            diff_c = cmd_len - ep["cmd_len_mean"]
            ep["cmd_len_mean"] += alpha * diff_c
            ep["cmd_len_std"] = math.sqrt((1 - alpha) * (ep["cmd_len_std"]**2) + alpha * (diff_c**2))

        # Command sequence tracking
        try:
            cmds = eval(row["command_sequence"]) if isinstance(row["command_sequence"], str) else row["command_sequence"]
            if isinstance(cmds, list):
                for cmd in cmds:
                    for token in cmd.split():
                        ep["commands_seen"].add(token)
                        peer["commands_seen"].add(token)
        except Exception:
            pass

    def get_profile(self, entity_id, entity_type):
        """
        Retrieves the profile for an entity.
        If event count < cold_start_threshold, returns peer-group baseline with is_cold_start = True.
        """
        ep = self.entity_profiles[entity_id]
        if ep["count"] < self.cold_start_threshold:
            peer = self.peer_profiles[entity_type]
            hours = peer["hours"] if peer["hours"] else [12.0]
            durations = peer["durations"] if peer["durations"] else [100.0]
            cmd_lens = peer["cmd_lens"] if peer["cmd_lens"] else [0.0]
            
            total_geo = sum(peer["geo_counts"].values()) or 1.0
            total_res = sum(peer["resource_counts"].values()) or 1.0
            total_auth = sum(peer["auth_counts"].values()) or 1.0

            return {
                "is_cold_start": True,
                "hour_mean": float(np.mean(hours)),
                "hour_std": float(np.std(hours)) + 1e-5,
                "duration_mean": float(np.mean(durations)),
                "duration_std": float(np.std(durations)) + 1e-5,
                "cmd_len_mean": float(np.mean(cmd_lens)),
                "cmd_len_std": float(np.std(cmd_lens)) + 1e-5,
                "geo_probs": {k: v / total_geo for k, v in peer["geo_counts"].items()},
                "resource_probs": {k: v / total_res for k, v in peer["resource_counts"].items()},
                "auth_probs": {k: v / total_auth for k, v in peer["auth_counts"].items()},
                "macs": set(),
                "fingerprints": set(),
                "commands_seen": peer["commands_seen"]
            }
        else:
            total_geo = sum(ep["geo_counts"].values()) or 1.0
            total_res = sum(ep["resource_counts"].values()) or 1.0
            total_auth = sum(ep["auth_counts"].values()) or 1.0

            return {
                "is_cold_start": False,
                "hour_mean": ep["hour_mean"],
                "hour_std": max(ep.get("hour_std", 1.0), 0.5),
                "duration_mean": ep["duration_mean"],
                "duration_std": max(ep.get("duration_std", 10.0), 1.0),
                "cmd_len_mean": ep.get("cmd_len_mean", 0.0),
                "cmd_len_std": max(ep.get("cmd_len_std", 1.0), 0.5),
                "geo_probs": {k: v / total_geo for k, v in ep["geo_counts"].items()},
                "resource_probs": {k: v / total_res for k, v in ep["resource_counts"].items()},
                "auth_probs": {k: v / total_auth for k, v in ep["auth_counts"].items()},
                "macs": ep["macs"],
                "fingerprints": ep["fingerprints"],
                "commands_seen": ep["commands_seen"]
            }
