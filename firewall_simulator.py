class Firewall:
    def __init__(self):
        # Default rules list: [Rule ID, Action, Source IP, Port, Protocol]
        self.rules = []

    def add_rule(self, action, source_ip="ANY", port="ANY", protocol="ANY"):
        rule_id = len(self.rules) + 1
        rule = {
            "id": rule_id,
            "action": action.upper(),
            "source_ip": source_ip,
            "port": str(port),
            "protocol": protocol.upper()
        }
        self.rules.append(rule)
        print(f"[+] Rule {rule_id} added: {rule['action']} IP={source_ip}, Port={port}, Protocol={protocol}")

    def inspect_packet(self, source_ip, port, protocol):
        port = str(port)
        protocol = protocol.upper()

        print(f"\n[INSPECTING PACKET] Incoming from IP: {source_ip} | Port: {port} | Protocol: {protocol}")

        # Evaluate packet against rules sequentially (First Match Wins)
        for rule in self.rules:
            ip_match = (rule["source_ip"] == "ANY" or rule["source_ip"] == source_ip)
            port_match = (rule["port"] == "ANY" or rule["port"] == port)
            proto_match = (rule["protocol"] == "ANY" or rule["protocol"] == protocol)

            if ip_match and port_match and proto_match:
                print(f" -> MATCHED RULE {rule['id']}: Action = {rule['action']}")
                return rule["action"]

        # Default action if no rule matches
        print(" -> NO MATCHING RULE: Default Action = BLOCK")
        return "BLOCK"


if __name__ == "__main__":
    fw = Firewall()

    print("=== CONFIGURING FIREWALL RULES ===")
    fw.add_rule(action="ALLOW", port=80, protocol="TCP")
    fw.add_rule(action="ALLOW", port=443, protocol="TCP")
    fw.add_rule(action="BLOCK", source_ip="192.168.1.50")
    fw.add_rule(action="ALLOW", source_ip="10.0.0.5", port=22, protocol="TCP")
    fw.add_rule(action="BLOCK", port=22, protocol="TCP")

    print("\n" + "="*45 + "\n")

    test_packets = [
        {"ip": "192.168.1.10", "port": 80, "protocol": "TCP"},
        {"ip": "192.168.1.50", "port": 80, "protocol": "TCP"},
        {"ip": "10.0.0.5",     "port": 22, "protocol": "TCP"},
        {"ip": "192.168.1.20", "port": 22, "protocol": "TCP"},
        {"ip": "192.168.1.30", "port": 53, "protocol": "UDP"},
    ]

    print("=== TESTING TRAFFIC FILTERING ===")
    for packet in test_packets:
        decision = fw.inspect_packet(packet["ip"], packet["port"], packet["protocol"])
        print(f" FINAL RESULT: Packet {decision}ED")