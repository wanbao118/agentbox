#!/usr/bin/env python3
"""
mxc policy generator skeleton
"""
import argparse
import json
import os

try:
    import yaml
    import jsonschema
except Exception:
    yaml = None
    jsonschema = None

TEMPLATE = {
    "version": "0.8.0-alpha",
    "process": {
        "commandLine": "echo 'hello from sandbox'",
        "env": ["EXAMPLE=1"]
    },
    "network": {
        "egress": {
            "default": "deny",
            "allow": []
        }
    }
}


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


def validate_schema(policy, schema_path):
    if jsonschema is None:
        print('jsonschema not installed; skipping validation')
        return True
    if not os.path.exists(schema_path):
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
        # TODO: translate capability declaration into MXC policy
        policy = TEMPLATE
        if isinstance(data, dict):
            # simple mapping example
            if 'allow_hosts' in data:
                for host in data.get('allow_hosts', []):
                    policy['network']['egress']['allow'].append({
                        "to": [{"cidr": host}],
                        "ports": [{"protocol": "tcp", "port": 443}]
                    })
    else:
        policy = TEMPLATE

    write_output(policy, args.output)

    if args.schema_path:
        try:
            validate_schema(policy, args.schema_path)
            print('policy validated against schema')
        except Exception as e:
            print('schema validation failed:', e)

if __name__ == '__main__':
    main()
