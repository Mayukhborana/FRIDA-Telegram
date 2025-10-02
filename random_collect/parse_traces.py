#!/usr/bin/env python3
# parse_traces.py
# Usage: python3 parse_traces.py tg_trace.jsonl tg_native_trace.jsonl

import json
import sys
import os
import csv

if len(sys.argv) < 3:
    print("Usage: python3 parse_traces.py <java_trace.jsonl> <native_trace.jsonl>")
    sys.exit(1)

java_file = sys.argv[1]
native_file = sys.argv[2]

output_dir = "parsed_output"
os.makedirs(output_dir, exist_ok=True)

java_summary_file = os.path.join(output_dir, "java_summary.csv")
native_summary_file = os.path.join(output_dir, "native_summary.csv")


def summarize(java_trace_file, native_trace_file):
    java_count = 0
    native_count = 0

    # --- Parse Java traces ---
    with open(java_trace_file, "r") as f, open(java_summary_file, "w", newline="") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(["timestamp", "class", "method", "args", "thread", "stack"])
        for line in f:
            try:
                j = json.loads(line)
                if j.get("type") != "java":
                    continue

                # Safe argument handling
                raw_args = j.get("args", [])
                if not isinstance(raw_args, list):
                    raw_args = []

                args_str = []
                for a in raw_args:
                    if isinstance(a, str):
                        args_str.append(a)
                    else:
                        try:
                            args_str.append(str(a))
                        except:
                            args_str.append("<unserializable>")

                stack0 = j.get("stack0", "")
                if not isinstance(stack0, str):
                    stack0 = ""

                writer.writerow([j.get("ts", ""), j.get("class", ""), j.get("method", ""), ";".join(args_str), j.get("thread", ""), stack0])
                java_count += 1
            except Exception as e:
                print(f"[JAVA_ROW_ERR] {e}")

    # --- Parse Native traces ---
    with open(native_trace_file, "r") as f, open(native_summary_file, "w", newline="") as out_f:
        writer = csv.writer(out_f)
        writer.writerow(["timestamp", "module", "symbol", "args", "stack"])
        for line in f:
            try:
                j = json.loads(line)
                if j.get("type") != "native":
                    continue

                raw_args = j.get("args", [])
                if not isinstance(raw_args, list):
                    raw_args = []

                args_str = []
                for a in raw_args:
                    try:
                        args_str.append(str(a))
                    except:
                        args_str.append("<unserializable>")

                stack0 = j.get("stack0", "")
                if not isinstance(stack0, str):
                    stack0 = ""

                writer.writerow([j.get("ts", ""), j.get("module", ""), j.get("symbol", ""), ";".join(args_str), stack0])
                native_count += 1
            except Exception as e:
                print(f"[NATIVE_ROW_ERR] {e}")

    print("Parsing complete.")
    print(f"  Java traces:   {java_count} lines -> {java_summary_file}")
    print(f"  Native traces: {native_count} lines -> {native_summary_file}")
    print(f"  Parsed output directory: {output_dir}")


summarize(java_file, native_file)
