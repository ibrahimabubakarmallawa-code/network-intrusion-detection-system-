
import logging
from collections import Counter
from datetime import datetime


# 1. CONFIGURE INCIDENT LOGGING


logging.basicConfig(
    filename="incident.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ----------------------------------
# 2. SAMPLE NETWORK PACKET DATA
# ----------------------------------

packets = [
    {"source": "192.168.1.10", "destination": "192.168.1.1", "port": 80, "protocol": "TCP"},
    {"source": "192.168.1.15", "destination": "192.168.1.1", "port": 443, "protocol": "TCP"},
    {"source": "192.168.1.20", "destination": "192.168.1.1", "port": 22, "protocol": "TCP"},
    {"source": "192.168.1.20", "destination": "192.168.1.1", "port": 22, "protocol": "TCP"},
    {"source": "192.168.1.20", "destination": "192.168.1.1", "port": 22, "protocol": "TCP"},
    {"source": "192.168.1.20", "destination": "192.168.1.1", "port": 22, "protocol": "TCP"},
    {"source": "192.168.1.30", "destination": "192.168.1.1", "port": 53, "protocol": "UDP"},
]


# ----------------------------------
# 3. DISPLAY NETWORK PACKETS
# ----------------------------------

def analyse_packets(packets):

    print("\n===== NETWORK PACKET REPORT =====")

    for packet in packets:

        print("Source IP:", packet["source"])
        print("Destination IP:", packet["destination"])
        print("Port:", packet["port"])
        print("Protocol:", packet["protocol"])
        print("--------------------------------")


# ----------------------------------
# 4. SUMMARIZE NETWORK TRAFFIC
# ----------------------------------

def summarize_traffic(packets):

    ip_counts = Counter(
        packet["source"] for packet in packets
    )

    print("\n===== TRAFFIC SUMMARY =====")

    for ip, count in ip_counts.items():

        print(f"{ip}: {count} packets")

    print("Total packets:", len(packets))

    return ip_counts


# ----------------------------------
# 5. DETECT SUSPICIOUS ACTIVITY
# ----------------------------------

def detect_intrusion(packets, threshold=4):

    attempts = Counter(
        (packet["source"], packet["port"])
        for packet in packets
    )

    print("\n===== SECURITY ANALYSIS =====")

    for (ip, port), count in attempts.items():

        if count >= threshold:

            message = (
                f"Possible suspicious activity: "
                f"IP {ip}, Port {port}, "
                f"Packet count {count}"
            )

            print("\nWARNING!")
            print(message)

            # Save the incident
            logging.warning(message)

        else:

            print(
                f"Normal traffic: {ip}, "
                f"Port {port}, Count: {count}"
            )


# ----------------------------------
# 6. MAIN FUNCTION
# ----------------------------------

def main():

    print("NETWORK INTRUSION DETECTION SYSTEM")
    print("==================================")

    print("Time:", datetime.now())

    analyse_packets(packets)

    summarize_traffic(packets)

    detect_intrusion(packets)

    print("\nAnalysis completed.")
    print("Check incident.log for recorded alerts.")


# ----------------------------------
# 7. RUN THE PROGRAM
# ----------------------------------

if __name__ == "__main__":
    main()
