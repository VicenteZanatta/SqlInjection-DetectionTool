import subprocess
import pyshark
import sys

def sql_injection_monitor(arg_interface, arg_port):
    print(f"Monitoring traffic in {arg_interface}, port {arg_port}...")
    print("Ctrl+C to stop\n")
    
    
    try:
        capture = pyshark.LiveCapture(interface = arg_interface, 
                                        display_filter=f'tcp.port=={arg_port}',
                                        decode_as={f'tcp.port=={arg_port}':'http'})
        for packet in capture:
            if hasattr(packet.tcp, 'payload'):                  # check if packet as payload
                if(payload_has_injection(packet.tcp.payload)):  # chek payload for SQL injection patterns
                    block_packet_source_ip(packet.ip.src)       # if payload has SQL injection, block sorce ip traffic at iptrables      

    except KeyboardInterrupt:
        print(f"\nMonitor Stopped")
        print(f"Captured Packeges {len(capture)}")

    except Exception as e:
        print(f"Error: {e}")
        print("Verify that the interface and port are valid and that you have permissions for packet capture")


def payload_has_injection(payload):
            
    sql_pattern = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 
                    'CREATE', 'DROP', 'ALTER', 'JOIN', 'UNION', 'EXEC']
    
    #decode from hex to humam readable text
    hex_split = payload.split(':')
    hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)
    payload_human_readable = ''.join(hex_as_chars)
    #print(f'Decoded payload: {payload_human_readable}')

    # check for each SQL pattern in packet payload
    for pattern in sql_pattern:
        if pattern in payload_human_readable.upper(): 
             print("SQL INJECTION DETECT")
             return True
        
    return False
                

def block_packet_source_ip(source_ip):
        try:
            # Block incoming traffic from source_ip
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'], check=True)
            print(f"IP {source_ip} blocked successfully!")
            
            # Block outgoing traffic to source_ip
            subprocess.run(['sudo', 'iptables', '-t', 'raw', '-I', 'PREROUTING', '-s', source_ip, '-j', 'DROP'], check=True)
            #subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', source_ip, '-j', 'DROP'], check=True)
            #print(f"Outgoing traffic to IP {source_ip} also blocked!")
            
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {source_ip}: {e}")    


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python script.py <interface> <port>")
        sys.exit(1)
    
    try:
        interface = sys.argv[1]
        porta = int(sys.argv[2])
        sql_injection_monitor(interface, porta)
    except ValueError:
        print("Error: invalid port number")
        sys.exit(1)