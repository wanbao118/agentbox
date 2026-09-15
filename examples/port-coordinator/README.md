# Simple coordinator service for port registration (Unix domain socket)

This script opens a unix domain socket (default /tmp/agentbox_port.sock) and accepts JSON lines from agents to register ports. It replies with a simple acknowledgment and logs registrations to stdout.
