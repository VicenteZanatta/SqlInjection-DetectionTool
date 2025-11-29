import subprocess
import pyshark
import sys

def sql_injection_monitor(arg_interface, arg_port):
    print(f"Monitorando tráfego na interface {arg_interface}, porta {arg_port}...")
    print("Pressione Ctrl+C para parar\n")
    
    try:
        capture = pyshark.LiveCapture(interface = arg_interface, 
                                        display_filter=f'tcp.port=={arg_port}',
                                        decode_as={f'tcp.port=={arg_port}':'http'})
        for packet in capture:
            if hasattr(packet.tcp, 'payload'):                  # check if packet as payload
                if(payload_has_injection(packet.tcp.payload)):  # chek payload for SQL injection patterns
                    block_packet_source_ip(packet.ip.src)       # if payload has SQL injection, block sorce ip traffic at iptrables      

    except KeyboardInterrupt:
        print(f"\nMonitoramento finalizado")
    except Exception as e:
        print(f"Erro: {e}")
        print("Verifique se a interface e porta são válidas e se você tem permissões para capturer pacotes")


def payload_has_injection(payload):
            
            sql_pattern = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 
                            'CREATE', 'DROP', 'ALTER', 'JOIN', 'UNION', 'EXEC']
            
            #decode from hex to humam readable text
            hex_split = payload.split(':')
            hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)
            payload_human_readable = ''.join(hex_as_chars)
            print(f'Decoded payload: {payload_human_readable}')

            for pattern in sql_pattern:
                if pattern in payload_human_readable.upper():
                     print("SQL INJECTION DETECT")
                     return True
                

def block_packet_source_ip(source_ip):
        try:
            # Block incoming traffic from source_ip
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'], check=True)
            print(f"IP {source_ip} blocked successfully!")
            
            # Block outgoing traffic to source_ip
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', source_ip, '-j', 'DROP'], check=True)
            print(f"Outgoing traffic to IP {source_ip} also blocked!")
            
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {source_ip}: {e}")    


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python script.py <interface> <porta>")
        sys.exit(1)
    
    try:
        interface = sys.argv[1]
        porta = int(sys.argv[2])
        sql_injection_monitor(interface, porta)
    except ValueError:
        print("Erro: A porta deve ser um número inteiro")
        sys.exit(1)