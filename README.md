# Firewall Rule Simulation and Traffic Filtering System

A Python-based simulation of network firewall rules that inspects incoming packets and determines whether to **ALLOW** or **BLOCK** traffic based on Source IP Address, Port Number, and Network Protocol.

## 🚀 Features
- **Sequential Rule Processing**: Evaluates packet parameters against rules in priority order (First-Match principle).
- **Wildcards (`ANY`)**: Supports wildcard matching for open rules (e.g., allowing HTTP traffic on Port 80 from any IP address).
- **Default Deny Strategy**: Automatically blocks packets that do not match any explicit allow rule.

## 🛠️ How to Run
```bash
python firewall_simulator.py