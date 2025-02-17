#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def is_unicast(mac_address):
    # bitul cel mai putin semnificativ = 0 => adresa unicast
    return int(mac_address.split(':')[0], 16) % 2 == 0

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# adaugam tag-ul VLAN inainte de adresa MAC destinatie
def add_vlan_tag(data, vlan_id):
    first = data[0:12] # iau separat primii 12 octeti (Destination MAC, Source MAC)
    last = data[12:] # iau separat ultimii octeti (EtherType, Payload)
    tag_vlan = create_vlan_tag(vlan_id) # creez tag-ul VLAN (adaug 4 octeti in mijloc)
    return first + tag_vlan + last # concatenare

# eliminam tag-ul VLAN
def remove_vlan_tag(data):
    res = data[0:12] + data[16:] # eliminam 4 octeti
    return res


# functie care trimite un BDPU pe toate interfetele
def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        
        time.sleep(1)


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    MAC_table = {} # dictionar care retine perechi (adresa MAC, interfata)
    access_ports = {} # dictionar cu interfetele care sunt access ports
    trunk_ports = [] # lista cu interfetele care sunt trunk ports

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    # construiesc calea fisierului de configurare
    config_path = f"configs/switch{switch_id}.cfg"
    
    # deschid fisierul de configurare in modul citire
    with open(config_path, "r") as config_file:
        config_file.readline() # trec peste prima linie
        # parcurg liniile ramase pentru configurarea porturilor
        for line in config_file:
            line = line.strip()
            if not line:
                continue
            
            port_id, vlan_id = line.split()
            
            if vlan_id == "T":
                trunk_ports.append(port_id)
            else:
                access_ports[port_id] = int(vlan_id)


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        MAC_table[src_mac] = interface
        
        curr_interface = get_interface_name(interface)
        if is_unicast(dest_mac):
            if dest_mac in MAC_table:
                dest_interface = MAC_table[dest_mac]
                
                #   daca interfata sursa este access port
                if curr_interface in access_ports:
                    # caz de access port -> access port (daca sunt in acelasi VLAN)
                    if get_interface_name(dest_interface) in access_ports and access_ports[curr_interface] == access_ports[get_interface_name(dest_interface)]:
                        send_to_link(dest_interface, length, data)
                    else:
                        # caz de access port -> trunk port cu adaugare de tag VLAN
                        data = add_vlan_tag(data, access_ports[curr_interface])
                        length += 4  
                        send_to_link(dest_interface, length, data)
                # daca interfata sursa este trunk port
                elif curr_interface in trunk_ports:
                    # caz de trunk port -> access port cu eliminare de tag VLAN
                    if get_interface_name(dest_interface) in access_ports and access_ports[get_interface_name(dest_interface)] == vlan_id:
                        data = remove_vlan_tag(data)
                        length -= 4 
                        send_to_link(dest_interface, length, data)
                    # caz de trunk port -> trunk port
                    else:
                        send_to_link(dest_interface, length, data)
            # daca adresa MAC destinatie nu se afla in tabela MAC
            else:
                length = len(data)
                for i in interfaces:
                    if i != interface:
                        if curr_interface in access_ports:
                            if get_interface_name(i) in trunk_ports:
                                data_with_tag = add_vlan_tag(data, access_ports[curr_interface])
                                send_to_link(i, length + 4, data_with_tag)
                            elif get_interface_name(i) in access_ports and access_ports[get_interface_name(i)] == access_ports[curr_interface]:
                                send_to_link(i, length, data)
                        elif curr_interface in trunk_ports:
                            if get_interface_name(i) in access_ports and access_ports[get_interface_name(i)] == vlan_id:
                                data_no_tag = remove_vlan_tag(data)
                                send_to_link(i, length - 4, data_no_tag)
                            elif get_interface_name(i) in trunk_ports:
                                send_to_link(i, length, data)
        # daca ma aflu pe cazul de broadcast
        else:
            length = len(data)
            for i in interfaces:
                if i != interface:
                    if curr_interface in access_ports:
                        if get_interface_name(i) in trunk_ports:
                            data_with_tag = add_vlan_tag(data, access_ports[curr_interface])
                            send_to_link(i, length + 4, data_with_tag)
                        elif get_interface_name(i) in access_ports and access_ports[get_interface_name(i)] == access_ports[curr_interface]:
                            send_to_link(i, length, data)
                    elif curr_interface in trunk_ports:
                        if get_interface_name(i) in access_ports and access_ports[get_interface_name(i)] == vlan_id:
                            data_no_tag = remove_vlan_tag(data)
                            send_to_link(i, length - 4, data_no_tag)
                        elif get_interface_name(i) in trunk_ports:
                            send_to_link(i, length, data)

        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(1, length, data)

if __name__ == "__main__":
    main()
