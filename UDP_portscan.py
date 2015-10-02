# Shreyas Damle
#!/usr/bin/env python
import sys
import logging
from time import strftime
from scapy.all import *

def main ():
    try: 
        print "UDP port scanner usnig python and scapy"
        target_ip = raw_input ("[-]Enter IP address of the target: ")
        min_port = raw_input ("[-]Enter the min port number: ")
        max_port = raw_input ("[-]Enter the max port number: ")
        
        try:
            if int(min_port)>= 0 and int (max_port) >= 0 and int(max_port) <= 65535 and int (max_port)> int (min_port):
                pass
            else:
                print "[!]Please eneter the valid range of the ports"
                print "Program is clsoing..."
                sys.exit [1]
        except Exception:
            print "Please enter the valid range of ports"
            print "Program is closing..."
            sys.exit [1]
    except KeyboardInterrupt:
        print "Program is closing due to user interruption"
        sys.exit [1]
        
        
    ports = range (int(min_port), int(max_port))
    DSTUNR = 0x0D
    
    def is_target_up(ip):
        conf.verb = 0 #To disable verbose
        ping = sr1 (IP(dst=ip)/ICMP())
        if ping == None:
             print "Couldn't resolve the target ip "
             print "Program is closing"
             return False
             sys.exit [1]
        else:
             print "Target is up. Scan started...."
             return True
             
    def scan_target(port):
        conf.verb = 0 
        source_port = RandShort() #Get a random source port
        ans = sr1(IP(dst=target_ip)/UDP(sport=source_port, dport=port),inter=0.5, retry=10, timeout=1)
        if ans == None:
            x, y = sr(IP(dst=target_ip)/UDP(sport=source_port,dport=port),inter=0.5,retry=10,timeout=1)
            y.summary()
        
            
       # for i in ans:
        #    if i.haslayer(ICMP):
         #       return True
          #  else:
           #     return False
        return ans
            
       
        
             

    
    is_target_up(target_ip)
    print "Scanning started at " + strftime ("%H:%M:%S") + "\n"
    
    for port in ports:
        state = scan_target(port)
        if  state == None:
            print "Port " + str(port) + ": Open"
        else:
            print "Port " + str(port) + ": Closed"
        
            
    print "[-]Scanning is complete!!!"
    
            
if __name__ == '__main__':
    main ()        
        
    

         
        
         
        

