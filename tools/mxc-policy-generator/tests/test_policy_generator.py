import unittest
import json
import tempfile
import os
from tools.mxc_policy_generator import main as gen_main  # note: not packaged; we'll run as module in test

# Since the generator is a script, we invoke it by importing functions indirectly.

class TestPolicyGenerator(unittest.TestCase):
    def test_build_policy_minimal(self):
        # use sample yaml
        sample = 'tools/mxc-policy-generator/sample_agent.yaml'
        out = tempfile.mktemp(suffix='.json')
        os.system(f'python tools/mxc-policy-generator/main.py --input {sample} --output {out}')
        with open(out, 'r') as f:
            p = json.load(f)
        self.assertIn('network', p)
        self.assertIn('process', p)
        os.remove(out)

if __name__ == '__main__':
    unittest.main()
