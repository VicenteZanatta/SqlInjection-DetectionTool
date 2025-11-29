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

            # protocol = packet.transport_layer
            # print(f"{protocol}")

            # source_address = packet.ip.src
            # print(f"{source_address}")

            # source_port = packet[packet.transport_layer].srcport
            # print(f"{source_port}")

            # destination_address = packet.ip.dst
            # print(f"{destination_address}")

            # destination_port = packet[packet.transport_layer].dstport
            # print(f"{destination_port}") 

            # packet_time = packet.sniff_time
            # print(f"{packet_time}")

            # packet_timestamp = packet.sniff_timestamp
            # print(f"{packet_timestamp}")

            if hasattr(packet.tcp, 'payload'):      # check if packet as payload
                if(payload_has_injection(packet.tcp.payload)):
                    block_ip_source(packet.ip.src)


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
                

def block_ip_source(source_ip):


            

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