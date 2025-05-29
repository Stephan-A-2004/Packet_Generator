from scapy.all import *
import threading
from Crypto.Cipher import AES

from Crypto.Util.Padding import pad

import tkinter as tkinter
from tkinter import *
from tkinter import ttk, messagebox
import ipaddress
import re


def send_packet(protocol, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, layer4_flags, encryption_status, payload, type_ICMP, code_ICMP): # For any argument you don't want to specify, leave blank in the GUI. If using the function without the GUI, different rules apply, see documentation.
    #Craft and send a packet based on specified attributes.
    try:
        ether_layer = Ether(src = ether_src, dst = ether_dst)
        ciphertext = payload
        if encryption_status == "Yes": # Encrypts payload if user selects
            key = b'm8oBLnXljmSkCI7g' # 16b (byte) password
            cipher = AES.new(key, AES.MODE_CBC)
            plaintext = str.encode(payload)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        elif encryption_status == 0 or encryption_status == None or encryption_status == "No":
            pass
        else:
            print(f"Invalid input: {encryption_status}")
            return
        ip_layer = IP(src=src_ip, dst=dst_ip)
    
        if protocol.upper() == "TCP" or protocol.upper() == 'UDP': # Makes protocol argument fully in uppercase letters
            if protocol.upper() == "TCP":
                if layer4_flags == None:
                    transport_layer = TCP(sport=src_port, dport=dst_port)
                else:
                    transport_layer = TCP(sport=src_port, dport=dst_port, flags=layer4_flags)
            else:
                transport_layer = UDP(sport=src_port, dport=dst_port)
            packet = ether_layer / ip_layer / transport_layer / Raw(ciphertext)
            sendp(packet, verbose=False) # Below print statements will show packet attributes
            print("== Packet Summary ==\n")
            print(f"{packet.summary()}\n\n")
            print("== Packet Details ==\n")
            print(f"{packet.show(dump=True)}\n")
        elif protocol.upper() == "ICMP":
            packet = ether_layer / ip_layer / ICMP(type = type_ICMP, code = code_ICMP) / Raw(ciphertext)
            sendp(packet, verbose=False) # Packet attributes for ICMP packet shown by these print statements
            print("== Packet Summary ==\n")
            print(f"{packet.summary()}\n\n")
            print("== Packet Details ==\n")
            print(f"{packet.show(dump=True)}\n")
        else:
            print(f"Unsupported protocol: {protocol}")
            return
        return f"== Packet Summary ==\n{packet.summary()}\n\n== Packet Details ==\n{packet.show(dump=True)}\n" # Packet attributes being outputted
    except:
        return "ERROR"
   
    
def create_packet(protocol, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, layer4_flags, encryption_status, payload, type_ICMP, code_ICMP): # For any argument you don't want to specify, leave blank in the GUI. If using the function without the GUI, different rules apply, see documentation.
    #Craft a packet based on specified attributes.
    try:
        ether_layer = Ether(src = ether_src, dst = ether_dst)
        ciphertext = payload
        if encryption_status == "Yes":
            key = b'sigmaskibidirizz' # 16b (byte) password
            cipher = AES.new(key, AES.MODE_CBC)
            plaintext = str.encode(payload)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        elif encryption_status == 0 or encryption_status == None or encryption_status == "No":
            pass
        else:
            print(f"Invalid input: {encryption_status}")
            return
        ip_layer = IP(src=src_ip, dst=dst_ip)
    
        if protocol.upper() == "TCP" or protocol.upper() == 'UDP': # Makes protocol argument fully in uppercase letters
            if protocol.upper() == "TCP":
                if layer4_flags == None:
                    transport_layer = TCP(sport=src_port, dport=dst_port)
                else:
                    transport_layer = TCP(sport=src_port, dport=dst_port, flags=layer4_flags)
            else:
                transport_layer = UDP(sport=src_port, dport=dst_port)
            packet = ether_layer / ip_layer / transport_layer / Raw(ciphertext)
            return f"== Packet Summary ==\n{packet.summary()}\n\n== Packet Details ==\n{packet.show(dump=True)}\n"
        elif protocol.upper() == "ICMP":
            packet = ether_layer / ip_layer / ICMP(type = type_ICMP, code = code_ICMP) / Raw(ciphertext)
            return f"== Packet Summary ==\n{packet.summary()}\n\n== Packet Details ==\n{packet.show(dump=True)}\n"
        else:
            print(f"Unsupported protocol: {protocol}")
            return 
    except:
        return "ERROR"

def start_sending(protocol, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, layer4_flags, encryption_status, payload, type_ICMP, code_ICMP):
    thread = threading.Thread(target=send_packet, args=(protocol, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, layer4_flags, encryption_status, payload, type_ICMP, code_ICMP))
    thread.start()
    return create_packet(protocol, ether_src, ether_dst, src_ip, dst_ip, src_port, dst_port, layer4_flags, encryption_status, payload, type_ICMP, code_ICMP) # To show output of the packet attributes, after sending the packet

##############################################################################################################################################################################
##############################################################################################################################################################################
##############################################################################################################################################################################

def show_input_fields(event):

    # Clear any previously created input fields
    for widget in frame_inputs.winfo_children():
        widget.destroy()

    # Number of input fields determined by the selected option
    labels=[]
    if dropdown1.get() == "TCP":
        number_of_inputs = 8
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "TCP Flags", "Payload"]
    elif dropdown1.get() == "UDP":
        number_of_inputs = 7
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "Payload"]
    elif dropdown1.get() == "ICMP":
        number_of_inputs = 7
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Payload", "ICMP type", "ICMP code"]
    else:
        number_of_inputs = 0  # No input fields if no valid option is selected

    # Creates the required amount of input fields
    for i in range(number_of_inputs):
        label = tkinter.Label(frame_inputs, text=labels[i])
        label.grid(row=i, column=0, padx=10, pady=5, sticky="w")
        entry = tkinter.Entry(frame_inputs)
        entry.grid(row=i, column=1, padx=10, pady=5)

def mac_address_validation(mac_address_arg):
        mac_address = mac_address_arg.strip().upper()
        mac_address = mac_address.replace('-', ':')
        pattern = r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$"
        if re.match(pattern, mac_address):
            return mac_address
        corrected_mac_address=""
        if not re.match(pattern, mac_address) and len(mac_address)==12:
            corrected_mac_address=f"{mac_address[0]}{mac_address[1]}"
            incrementer=0
            characters=[]
            for i in range(10):
                characters.append(mac_address[i+2])
            for i in range(5):
                corrected_mac_address = f"{corrected_mac_address}:{characters[i+incrementer]}{characters[i+1+incrementer]}"
                incrementer+=1
                if i==4:
                    incrementer+=1
        if not re.match(pattern, corrected_mac_address):
            raise ValueError("Invalid MAC address format")
        else:
            return corrected_mac_address
def port_number_validation(port_number_arg):
    try:
        port_number_arg = int(port_number_arg)
        if not (0 <= int(port_number_arg) <= 65535):
            raise Exception("")
    except:
        raise ValueError("Invalid Port", "Port numbers must be between 0 and 65535.")


def send_packet_button_clicked():

    if dropdown1.get() == "" and dropdown2.get() == "":
        messagebox.showwarning("Incomplete dropdown menu selection", "Please select an option from Protocols and an Encryption option of the payload.")
        return
    elif dropdown1.get() == "":
        messagebox.showwarning("Incomplete dropdown menu selection", "Please select an option from Protocols.")
        return
    elif dropdown2.get() == "":
        messagebox.showwarning("Incomplete dropdown menu selection", "Please select an option from Encryption options of the payload.")
        return

    # Clear previous output
    output_label.config(text="")

    # Collect all input values, set empty ones to None
    inputs = []

    
    for widget in frame_inputs.winfo_children():
        if isinstance(widget, tkinter.Entry): 

            # If the field is empty, set it to None
            if widget.get() == "" or widget.get() == "None" or widget.get() == None:
                inputs.append(None)
            else:
                inputs.append(widget.get())  

    success_message = ""
    
        
    if dropdown1.get() == "TCP":
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "TCP Flags", "Payload"]
        error_count=0
        if dropdown2.get() == "Yes" and inputs[7]==None:
            try:
                raise ValueError("Payload field can't be left blank if packet encrypted option is selected to be yes")
            except:
                messagebox.showerror("Put in a payload", "Payload field can't be left blank if encrypting the packet")
                error_count+=1
        else:
            try:
                # Validate MAC addresses
                if inputs[0] != None:
                    inputs[0] = mac_address_validation(inputs[0])
                        
                if inputs[1] != None:
                    inputs[1] = mac_address_validation(inputs[1])    
            except ValueError:
                messagebox.showerror("Invalid MAC", "Please enter valid MAC addresses.")
                error_count+=1
            try:
                # Validate IP addresses
                if inputs[2] != None:
                    ipaddress.ip_address(inputs[2])
                ipaddress.ip_address(inputs[3])      
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
                error_count+=1
            try:
                # Validate Port Numbers
                if inputs[4] is not None:
                    port_number_validation(inputs[4])
                    inputs[4] = int(inputs[4])
                if inputs[5] is None:
                    raise ValueError("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank")
                else:
                    inputs[5] = int(inputs[5])
                    port_number_validation(inputs[5])
            except:
                messagebox.showerror("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank "+str(type(inputs[4])))
                error_count+=1
            try:
                list_flags=["S", "A", "F", "P", "R", "U", "E", "C", "N"]
                a=inputs[0] # Source MAC address
                b=inputs[1] # Destination MAC address
                c=inputs[2] # Source IP address
                d=inputs[3] # Destination IP address
                e1=inputs[4] # Source port number
                f=inputs[5] # Destination port number
                g=inputs[6] # TCP flags
                h=inputs[7] # Payload
                i1=None # Set to None as TCP doesn't have ICMP type
                j1=None # Set to None as TCP doesn't have ICMP code
                if g != None:
                    g=g.upper()
                    for i in range(len(g)):
                        for j in range(9):
                            if g[i] == list_flags[j]:
                                j=0
                                break
                        if j != 0:
                            error_count+=1
                            raise ValueError("Invalid flag or flags")
                if g==None:
                    g=""
                if h==None:
                    h=""
            except:
                messagebox.showerror("Invalid flag or flags", "Flags must be left blank, or be any combination of S, A, F, R, P, U, E, C, N. Combinations of the flags must have no spaces in between them"+str(type(inputs[7])))
            try:
                if error_count==0:
                    success_message = start_sending("tcp", a, b, c, d, e1, f, g, dropdown2.get(), h, i1, j1)
                else:
                    raise Exception("Invalid input or inputs")
            except:
                pass
        

    elif dropdown1.get() == "UDP":
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "Payload"]
        error_count=0
        if dropdown2.get() == "Yes" and inputs[6]==None:
            try:
                raise ValueError("Payload field can't be left blank if packet encrypted option is selected to be yes")
            except:
                messagebox.showerror("Put in a payload", "Payload field can't be left blank if encrypting the packet")
                error_count+=1
        else:
            try:
                # Validate MAC addresses
                if inputs[0] != None:
                    inputs[0] = mac_address_validation(inputs[0])
                        
                    #mac2str(inputs[0])
                if inputs[1] != None:
                    inputs[1] = mac_address_validation(inputs[1])
                    #mac2str(inputs[1])      
            except ValueError:
                messagebox.showerror("Invalid MAC", "Please enter valid MAC addresses.")
                error_count+=1
            try:
                # Validate IP addresses
                if inputs[2] != None:
                    ipaddress.ip_address(inputs[2])
                ipaddress.ip_address(inputs[3])      
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
                error_count+=1
            try:
                # Validate Port Numbers
                if inputs[4] is not None:
                    port_number_validation(inputs[4])
                    inputs[4] = int(inputs[4])
                    #messagebox.showerror()
                if inputs[5] is None:
                    raise ValueError("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank")
                else:
                    inputs[5] = int(inputs[5])
                    port_number_validation(inputs[5])
            except:
                messagebox.showerror("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank ")
                error_count+=1
            
            try:
                a=inputs[0] # Source MAC address
                b=inputs[1] # Destination MAC address
                c=inputs[2] # Source IP address
                d=inputs[3] # Destination IP address
                e1=inputs[4] # Source port number
                f=inputs[5] # Destination port number
                g=None # Set to None as udp doesn't have flags
                h=inputs[6] # Payload
                i1=None # Set to None as UDP doesn't have ICMP type
                j1=None # Set to None as UDP doesn't have ICMP code
                if h==None:
                    h=""
                if error_count==0:
                    success_message = start_sending("udp", a, b, c, d, e1, f, g, dropdown2.get(), h, i1, j1)
                else:
                    raise Exception("Invalid input or inputs")
            except:
                pass

    elif dropdown1.get() == "ICMP":
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Payload", "ICMP type", "ICMP code"]
        error_count=0
        if dropdown2.get() == "Yes" and inputs[4]==None:
            try:
                raise ValueError("Payload field can't be left blank if packet encrypted option is selected to be yes")
            except:
                messagebox.showerror("Put in a payload", "Payload field can't be left blank if encrypting the packet")
                error_count+=1
        else:
            try:
                # Validate MAC addresses
                if inputs[0] != None:
                    inputs[0] = mac_address_validation(inputs[0])
                        
                    #mac2str(inputs[0])
                if inputs[1] != None:
                    inputs[1] = mac_address_validation(inputs[1])
                    #mac2str(inputs[1])      
            except ValueError:
                messagebox.showerror("Invalid MAC", "Please enter valid MAC addresses.")
                error_count+=1
            try:
                # Validate IP addresses
                if inputs[2] != None:
                    ipaddress.ip_address(inputs[2])
                ipaddress.ip_address(inputs[3])      
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
                error_count+=1           
            try:
                a=inputs[0] # Source MAC address
                b=inputs[1] # Destination MAC address
                c=inputs[2] # Source IP address
                d=inputs[3] # Destination IP address
                e1=None # Set to None as ICMP doesn't have Source port number
                f=None # Set to None as ICMP doesn't have Destination port number
                g=None # Set to None as icmp doesn't have flags
                h=inputs[4] # Payload
                i1=inputs[5] # ICMP type
                j1=inputs[6] # ICMP code

                inputs[5]=i1
                inputs[6]=j1

                if h==None:
                    h=""
                if i1==None:
                    i1=8
                else:
                    i1=int(i1)
                if j1==None:
                    j1=0
                else:
                    j1=int(j1)
                if not 0 <= i1 <= 255:
                    raise Exception("Invalid ICMP type or ICMP code")
                if not 0 <= j1 <= 255:
                    raise Exception("Invalid ICMP type or ICMP code")
            except:
                messagebox.showerror("Invalid ICMP type or ICMP code, both values must be type integer and meet below rules:", "0<= ICMP type <= 255 and 0<= ICMP code <= 255.")
                error_count+=1000000
            try:    
                if error_count==0:
                    success_message = start_sending("ICMP", a, b, c, d, None, None, None, dropdown2.get(), h, i1, j1)
                else:
                    raise Exception("Invalid input or inputs")
            except:
                if error_count>=1000000:
                    messagebox.showerror("Invalid combination of ICMP type and ICMP value."," Information on valid combinations of ICMP type and ICMP value can be found on: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types")
                else:
                    pass

    # Display the output
    output_label.config(text=success_message)

def create_packet_button_clicked():

    if dropdown1.get() == "" and dropdown2.get() == "":
        messagebox.showwarning("Incomplete dropdown menu selection", "Please select an option from Protocols and an Encryption option of the payload.")
        return
    elif dropdown1.get() == "":
        messagebox.showwarning("Incomplete dropdown menu selection", "Please select an option from Protocols.")
        return
    elif dropdown2.get() == "":
        messagebox.showwarning("Incomplete dropdown menu selection", "Please select an option from Encryption options of the payload.")
        return

    # Clear previous output
    output_label.config(text="")

    # Collect all input values, set empty ones to None
    inputs = []

   
    for widget in frame_inputs.winfo_children():
        if isinstance(widget, tkinter.Entry):  

            # If the field is empty, set it to None
            if widget.get() == "" or widget.get() == "None" or widget.get() == None:
                inputs.append(None)
            else:
                inputs.append(widget.get())  
   
    success_message = ""
    
        
    if dropdown1.get() == "TCP":
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "TCP Flags", "Payload"]
        error_count=0
        if dropdown2.get() == "Yes" and inputs[7]==None:
            try:
                raise ValueError("Payload field can't be left blank if packet encrypted option is selected to be yes")
            except:
                messagebox.showerror("Put in a payload", "Payload field can't be left blank if encrypting the packet")
                error_count+=1
        else:
            try:
                # Validate MAC addresses
                if inputs[0] != None:
                    inputs[0] = mac_address_validation(inputs[0])
                        
                    
                if inputs[1] != None:
                    inputs[1] = mac_address_validation(inputs[1])
                        
            except ValueError:
                messagebox.showerror("Invalid MAC", "Please enter valid MAC addresses.")
                error_count+=1
            try:
                # Validate IP addresses
                if inputs[2] != None:
                    ipaddress.ip_address(inputs[2])
                ipaddress.ip_address(inputs[3])      
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
                error_count+=1
            try:
                # Validate Port Numbers
                if inputs[4] is not None:
                    port_number_validation(inputs[4])
                    inputs[4] = int(inputs[4])
                    
                if inputs[5] is None:
                    raise ValueError("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank")
                else:
                    inputs[5] = int(inputs[5])
                    port_number_validation(inputs[5])
            except:
                messagebox.showerror("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank "+str(type(inputs[4])))
                error_count+=1
            try:
                list_flags=["S", "A", "F", "P", "R", "U", "E", "C", "N"]
                a=inputs[0] # Source MAC address
                b=inputs[1] # Destination MAC address
                c=inputs[2] # Source IP address
                d=inputs[3] # Destination IP address
                e1=inputs[4] # Source port number
                f=inputs[5] # Destination port number
                g=inputs[6] # TCP flags
                h=inputs[7] # Payload
                i1=None # Set to None as TCP doesn't have ICMP type
                j1=None # Set to None as TCP doesn't have ICMP code
                if g != None:
                    g=g.upper()
                    for i in range(len(g)):
                        for j in range(9):
                            if g[i] == list_flags[j]:
                                j=0
                                break
                        if j != 0:
                            error_count+=1
                            raise ValueError("Invalid flag or flags")
                if g==None:
                    g=""
                if h==None:
                    h=""
            except:
                messagebox.showerror("Invalid flag or flags", "Flags must be left blank, or be any combination of S, A, F, R, P, U, E, C, N. Combinations of the flags must have no spaces in between them"+str(type(inputs[7])))
            try:
                if error_count==0:
                    success_message = create_packet("tcp", a, b, c, d, e1, f, g, dropdown2.get(), h, i1, j1)
                else:
                    raise Exception("Invalid input or inputs")
            except:
                pass
        

    elif dropdown1.get() == "UDP":
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "Payload"]
        error_count=0
        if dropdown2.get() == "Yes" and inputs[6]==None:
            try:
                raise ValueError("Payload field can't be left blank if packet encrypted option is selected to be yes")
            except:
                messagebox.showerror("Put in a payload", "Payload field can't be left blank if encrypting the packet")
                error_count+=1
        else:
            try:
                # Validate MAC addresses
                if inputs[0] != None:
                    inputs[0] = mac_address_validation(inputs[0])
                        
                if inputs[1] != None:
                    inputs[1] = mac_address_validation(inputs[1])     
            except ValueError:
                messagebox.showerror("Invalid MAC", "Please enter valid MAC addresses.")
                error_count+=1
            try:
                # Validate IP addresses
                if inputs[2] != None:
                    ipaddress.ip_address(inputs[2])
                ipaddress.ip_address(inputs[3])      
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
                error_count+=1
            try:
                # Validate Port Numbers
                if inputs[4] is not None:
                    port_number_validation(inputs[4])
                    inputs[4] = int(inputs[4])
                if inputs[5] is None:
                    raise ValueError("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank")
                else:
                    inputs[5] = int(inputs[5])
                    port_number_validation(inputs[5])
            except:
                messagebox.showerror("Invalid Port", "Port numbers must be between 0 and 65535, Destination Port can't be left blank ")
                error_count+=1
            
            try:
                a=inputs[0] # Source MAC address
                b=inputs[1] # Destination MAC address
                c=inputs[2] # Source IP address
                d=inputs[3] # Destination IP address
                e1=inputs[4] # Source port number
                f=inputs[5] # Destination port number
                g=None # Set to None as udp doesn't have flags
                h=inputs[6] # Payload
                i1=None # Set to None as UDP doesn't have ICMP type
                j1=None # Set to None as UDP doesn't have ICMP code
                if h==None:
                    h=""
                if error_count==0:
                    success_message = create_packet("udp", a, b, c, d, e1, f, g, dropdown2.get(), h, i1, j1)
                else:
                    raise Exception("Invalid input or inputs")
            except:
               pass

    elif dropdown1.get() == "ICMP":
        labels=["Source MAC Address", "Destination MAC Address", "Source IP Address", "Destination IP Address", "Payload", "ICMP type", "ICMP code"]
        error_count=0
        if dropdown2.get() == "Yes" and inputs[4]==None:
            try:
                raise ValueError("Payload field can't be left blank if packet encrypted option is selected to be yes")
            except:
                messagebox.showerror("Put in a payload", "Payload field can't be left blank if encrypting the packet")
                error_count+=1
        else:
            try:
                # Validate MAC addresses
                if inputs[0] != None:
                    inputs[0] = mac_address_validation(inputs[0])
                        
                if inputs[1] != None:
                    inputs[1] = mac_address_validation(inputs[1])     
            except ValueError:
                messagebox.showerror("Invalid MAC", "Please enter valid MAC addresses.")
                error_count+=1
            try:
                # Validate IP addresses
                if inputs[2] != None:
                    ipaddress.ip_address(inputs[2])
                ipaddress.ip_address(inputs[3])      
            except ValueError:
                messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
                error_count+=1           
            try:
                a=inputs[0] # Source MAC address
                b=inputs[1] # Destination MAC address
                c=inputs[2] # Source IP address
                d=inputs[3] # Destination IP address
                e1=None # Set to None as ICMP doesn't have Source port number
                f=None # Set to None as ICMP doesn't have Destination port number
                g=None # Set to None as icmp doesn't have flags
                h=inputs[4] # Payload
                i1=inputs[5] # ICMP type
                j1=inputs[6] # ICMP code

                inputs[5]=i1
                inputs[6]=j1

                if h==None:
                    h=""
                if i1==None:
                    i1=8
                else:
                    i1=int(i1)
                if j1==None:
                    j1=0
                else:
                    j1=int(j1)
                if not 0 <= i1 <= 255:
                    raise Exception("Invalid ICMP type or ICMP code")
                if not 0 <= j1 <= 255:
                    raise Exception("Invalid ICMP type or ICMP code")
            except:
                messagebox.showerror("Invalid ICMP type or ICMP code, both values must be type integer and meet below rules:", "0<= ICMP type <= 255 and 0<= ICMP code <= 255.")
                error_count+=1000000
            try:    
                if error_count==0:
                    success_message = create_packet("ICMP", a, b, c, d, None, None, None, dropdown2.get(), h, i1, j1)
                else:
                    raise Exception("Invalid input or inputs")
            except:
                if error_count>=1000000:
                    messagebox.showerror("Invalid combination of ICMP type and ICMP value."," Information on valid combinations of ICMP type and ICMP value can be found on: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types")
                else:
                    pass

    # Display the output
    output_label.config(text=success_message)

# Create the main window
main_window = tkinter.Tk()
main_window.title("Scapy Packet Maker GUI")

# Frame for the dropdown menus and start button
frame_top = tkinter.Frame(main_window)
frame_top.pack(pady=20)
###################################### FIRST DROPDOWN MENU ############################################
# First dropdown menu (Dropdown 1)
'''''
This dropdown menu allows the user to pick which protocol a generated packet will be
'''''
dropdown1_label = tkinter.Label(frame_top, text="Select which protocol the packet should be:")
dropdown1_label.pack(side=tkinter.LEFT, padx=10)

dropdown1 = ttk.Combobox(frame_top, values=["", "TCP", "UDP", "ICMP"])
dropdown1.pack(side=tkinter.LEFT, padx=10)
dropdown1.bind("<<ComboboxSelected>>", show_input_fields)
##################################### SECOND DROPDOWN MENU ############################################

'''''
This dropdown menu allows the user to pick if a generated packet will have an encrypted payload or be unencrypted
'''''
# Second dropdown menu (Dropdown 2)
dropdown2_label = tkinter.Label(frame_top, text="Do you want to encrypt the packet payload:")
dropdown2_label.pack(side=tkinter.LEFT, padx=10)

dropdown2 = ttk.Combobox(frame_top, values=["", "Yes", "No"])
dropdown2.pack(side=tkinter.LEFT, padx=10)

# Frame for the input fields
frame_inputs = tkinter.Frame(main_window)
frame_inputs.pack(pady=10)

def clear_button_clicked():
    # Clear all input fields
    for widget in frame_inputs.winfo_children():
        widget.destroy()
    dropdown1.set('')
    dropdown2.set('')
# Clear button on the far right
clear_inputs_button = tkinter.Button(main_window, text="Clear", command=clear_button_clicked)
clear_inputs_button.pack(side=tkinter.RIGHT, padx=20, pady=10)

# Send packet button on the far right
send_packet_button = tkinter.Button(main_window, text="Send Packet", command=send_packet_button_clicked)
send_packet_button.pack(side=tkinter.RIGHT, padx=20, pady=10)

# Create packet button on the far right
create_packet_button = tkinter.Button(main_window, text="Create Packet", command=create_packet_button_clicked)
create_packet_button.pack(side=tkinter.RIGHT, padx=20, pady=10)

####################################### OUTPUT DISPLAY FRAME ########################################
# Frame for displaying the output
output_frame = tkinter.Frame(main_window)
output_frame.pack()  # Adjust the padding here to shift the output frame to the right

# Label to display the results after clicking Start
output_label = tkinter.Label(output_frame, text="Outputs will appear here.", justify=tkinter.LEFT)
output_label.pack()
###################################### RUN THE APPLICATION ##########################################
# Run the application
main_window.mainloop()


#################################################################################################################################



