#!/usr/bin/env python3
"""
Enhanced mxc policy generator (simple mapping)
"""
import argparse
import json
import os
import re

try:
    import yaml
    import jsonschema
except Exception:
    yaml = None
    jsonschema = None


def is_cidr(s):
    # rudimentary CIDR detection
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", s))


def load_input(path):
    if path.endswith(('.yaml', '.yml')):
        if yaml is None:
            raise RuntimeError('pyyaml is required')
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    else:
        with open(path, 'r') as f:
            return json.load(f)


def write_output(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(obj, f, indent=2)


def make_network_section(data):
    net = {
        "egress": {
            "default": "deny",
            "allow": [],
            "deny": []
        },
        "ingress": {
            "default": "deny",
            "hostLoopback": "deny"
        },
        "allowedHosts": [],
        "blockedHosts": []
    }

    # allowed hosts (domain names) -> put in allowedHosts
    for h in data.get('allow_hosts', []) or []:
        if is_cidr(str(h)):
            # map CIDR to egress.allow.to
            net['egress']['allow'].append({
                "to": [{"cidr": str(h)}],
                "ports": [{"protocol": "tcp"}]
            })
        else:
            net['allowedHosts'].append(str(h))

    # extra CIDRs
    for cidr in data.get('allow_cidrs', []) or []:
        net['egress']['allow'].append({
            "to": [{"cidr": str(cidr)}],
            "ports": [{"protocol": "tcp"}]
        })

    # ports mapping if provided as list of ints or ranges
    ports = data.get('ports', []) or []
    if ports:
        # attach ports to each allow rule if any; otherwise create a wide allow rule
        if net['egress']['allow']:
            for rule in net['egress']['allow']:
                rule_ports = []
                for p in ports:
                    if isinstance(p, int):
                        rule_ports.append({"protocol": "tcp", "port": p})
                    elif isinstance(p, str) and '-' in p:
                        start, end = p.split('-', 1)
                        rule_ports.append({"protocol": "tcp", "port": int(start), "endPort": int(end)})
                    else:
                        try:
                            ip = int(p)
                            rule_ports.append({"protocol": "tcp", "port": ip})
                        except Exception:
                            pass
                if rule_ports:
                    rule['ports'] = rule_ports
        else:
            # no allow rules: create a generic allow to 0.0.0.0/0 with specified ports
            rp = []
            for p in ports:
                if isinstance(p, int):
                    rp.append({"protocol": "tcp", "port": p})
                elif isinstance(p, str) and '-' in p:
                    start, end = p.split('-', 1)
                    rp.append({"protocol": "tcp", "port": int(start), "endPort": int(end)})
            if rp:
                net['egress']['allow'].append({"to": [{"cidr": "0.0.0.0/0"}], "ports": rp})

    return net


def make_filesystem_section(data):
    fs = {}
    if data.get('readonly_paths'):
        fs['readonlyPaths'] = list(data['readonly_paths'])
    if data.get('readwrite_paths'):
        fs['readwritePaths'] = list(data['readwrite_paths'])
    if data.get('denied_paths'):
        fs['deniedPaths'] = list(data['denied_paths'])
    return fs


def make_process_section(data):
    proc = {
        "commandLine": data.get('command_line') or None,
        "cwd": data.get('cwd') or None,
        "env": None
    }
    env = data.get('env') or {}
    if env:
        proc['env'] = [f"{k}={v}" for k, v in env.items()]
    return proc


def build_policy(data):
    policy = {
        "version": "0.8.0-alpha",
        "process": None,
        "filesystem": None,
        "network": None,
        "runtimeConfig": None
    }

    policy['process'] = make_process_section(data)
    fs = make_filesystem_section(data)
    if fs:
        policy['filesystem'] = fs
    net = make_network_section(data)
    policy['network'] = net

    # runtimeConfig example: set networkProxy to envoy loopback
    policy['runtimeConfig'] = {"networkProxy": data.get('network_proxy') or "http://127.0.0.1:15000"}

    # remove keys with None
    policy = {k: v for k, v in policy.items() if v is not None}
    return policy


def validate_schema(policy, schema_path):
    if jsonschema is None:
        print('jsonschema not installed; skipping validation')
        return True
    if not schema_path or not os.path.exists(schema_path):
        print('schema not found; skipping validation')
        return True
    with open(schema_path, 'r') as f:
        schema = json.load(f)
    jsonschema.validate(policy, schema)
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', required=False, help='capability declaration YAML/JSON')
    p.add_argument('--output', required=True, help='output policy JSON path')
    p.add_argument('--schema-path', required=False, help='path to mxc schema json')
    args = p.parse_args()

    if args.input:
        data = load_input(args.input)
    else:
        data = {}

    policy = build_policy(data)
    write_output(policy, args.output)
    print('policy written to', args.output)

    if args.schema_path:
        try:
            validate_schema(policy, args.schema_path)
            print('policy validated against schema')
        except Exception as e:
            print('schema validation failed:', e)


if __name__ == '__main__':
    main()
