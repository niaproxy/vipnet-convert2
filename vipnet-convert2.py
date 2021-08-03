#!/usr/bin/python3
#-*- coding: utf-8 -*-

from tkinter import *  
#import tkFileDialog as filedialog
from tkinter import messagebox
import re
from netaddr import IPAddress

window = Tk()  
window.title("Конвертация конфига")  
window.geometry('1100x980')    
frame = Frame(window)
header = Label(frame, text="Исходный конфиг ASA                                                  Конфиг VipNet", font=("Arial Bold", 14), padx=15, pady=15)
header.pack( side = TOP)
asa_config = ""
vipnet_config = ""
asa_box = Text(
    frame,
    height=50,
    width=65,
    wrap='word'
)    
vipnet_box = Text(
    frame,
    height=50,
    width=65,
    wrap='word'
)
def select_text():
   vipnet_box.tag_add("start", "1.0","end")
   vipnet_box.tag_configure("start",background="black", foreground= "white")
   copy_text()
#   asa_box.get("start",'1.0', 'end')
#   window.withdraw()
def copy_text():
   window.clipboard_clear()
   window.clipboard_append(vipnet_box.get('1.0', 'end'))
   window.update()


sb = Scrollbar(frame)
sb.pack(side=RIGHT, fill=BOTH)
asa_box.pack(side=LEFT,expand=True)
vipnet_box.pack(side=RIGHT,expand=True)
m = Menu(window, tearoff=0)
m.add_command(label="Копировать результат в буфер обмена",command=select_text)
#m.add_command(label="Выделить все",command=select_text)
asa_box.config(yscrollcommand=sb.set)
#sb.config(command=asa_box.yview)
sb.config(command=vipnet_box.yview)
frame.pack(expand=True)
runcount=0
Keyword="15920951887333659761"
def demo_mode():
    global runcount
    if runcount == 0:
        onetimekey=str(random.getrandbits(16))
        hash=onetimekey+str(Keyword)
        trial_key_true = hashlib.md5(hash.encode())
        trial_key = simpledialog.askstring('','Для получения пробного ключа отправьте код:\n                                    %s\n на адрес samohin-iv@utg.gazprom.ru' % onetimekey)
        if trial_key == trial_key_true.hexdigest():
            runcount = 1
    if runcount <= 3 and runcount != 0:
        convert_config()
    else:
        messagebox.showerror('', 'Количество пробных запросов превышено.\nЗапросите новый ключ.')
#Offical ASA ports
#https://www.cisco.com/c/en/us/td/docs/security/asa/asa96/configuration/general/asa-96-general-config/ref-ports.html#ID-2120-000002b8
def change_asa_service(port):
    if port == "aol":
     port = 5190
    if port == "bgp":
     port = 179
    if port == "biff":
     port = 512
    if port == "bootpc":
     port = 68
    if port == "bootps":
     port = 67
    if port == "chargen":
     port = 19
    if port == "cifs":
     port = 3020
    if port == "citrix-ica":
     port = 1494
    if port == "cmd":
     port = 514
    if port == "ctiqbe":
     port = 2748
    if port == "daytime":
     port = 13
    if port == "discard":
     port = 9
    if port == "dnsix":
     port = 195
    if port == "domain":
     port = 53
    if port == "echo":
     port = 7
    if port == "exec":
     port = 512
    if port == "finger":
     port = 79
    if port == "ftp":
     port = 21
    if port == "ftp-data":
     port = 20
    if port == "gopher":
     port = 70
    if port == "h323":
     port = 1720
    if port == "hostname":
     port = 101
    if port == "http":
     port = 80
    if port == "https":
     port = 443
    if port == "ident":
     port = 113
    if port == "imap4":
     port = 143
    if port == "irc":
     port = 194
    if port == "isakmp":
     port = 500
    if port == "kerberos":
     port = 750
    if port == "klogin":
     port = 543
    if port == "kshell":
     port = 544
    if port == "ldap":
     port = 389
    if port == "ldaps":
     port = 636
    if port == "login":
     port = 513
    if port == "lotusnotes":
     port = 1352
    if port == "lpd":
     port = 515
    if port == "mobile-ip":
     port = 434
    if port == "nameserver":
     port = 42
    if port == "netbios-dgm":
     port = 138
    if port == "netbios-ns":
     port = 137
    if port == "netbios-ssn":
     port = 139
    if port == "nfs":
     port = 2049
    if port == "nntp":
     port = 119
    if port == "ntp":
     port = 123
    if port == "pcanywhere-data":
     port = 5631
    if port == "pcanywhere-status":
     port = 5632
    if port == "pim-auto-rp":
     port = 496
    if port == "pop2":
     port = 109
    if port == "pop3":
     port = 110
    if port == "pptp":
     port = 1723
    if port == "radius":
     port = 1645
    if port == "radius-acct":
     port = 1646
    if port == "rip":
     port = 520
    if port == "rsh":
     port = 514
    if port == "rtsp":
     port = 554
    if port == "secureid-udp":
     port = 5510
    if port == "sip":
     port = 5060
    if port == "smtp":
     port = 25
    if port == "snmp":
     port = 161
    if port == "snmptrap":
     port = 162
    if port == "sqlnet":
     port = 1521
    if port == "ssh":
     port = 22
    if port == "sunrpc":
     port = 111
    if port == "syslog":
     port = 514
    if port == "tacacs":
     port = 49
    if port == "talk":
     port = 517
    if port == "telnet":
     port = 23
    if port == "tftp":
     port = 69
    if port == "time":
     port = 37
    if port == "uucp":
     port = 540
    if port == "vxlan":
     port = 4789
    if port == "who":
     port = 513
    if port == "whois":
     port = 43
    if port == "www":
     port = 80
    if port == "xdmcp":
     port = 177
    return str(port)
def do_popup(event):
    try:
        m.tk_popup(event.x_root, event.y_root)
    finally:
        m.grab_release()
def parse_accesslist(id,lst,nets):
     try:
     #id=5
      if lst[id] == "object-group":
        source =','.join(map(str,nets.get(lst[id+1])))
        if lst[id+2] == "object-group":
          destination = ','.join(map(str,nets.get(lst[id+3])))
        elif lst[id+2] == "object":
          destination = "@%s" % lst[id+3]
        else:
          mask = str(IPAddress(lst[id+3]).netmask_bits())
          if lst[id+2] == "host":
             destination = lst[id+3] + "/" + mask
          else:
             destination = lst[id+2] + "/" + mask
      elif lst[id] == "object":
        source = "@%s" % lst[id+1]
        if lst[id+2] == "object-group":
          destination = ','.join(map(str,nets.get(lst[id+3])))
        elif lst[id+2] == "object":
          destination = "@%s" % lst[id+3]
        else:
          mask = str(IPAddress(lst[id+3]).netmask_bits())
          if lst[id+2] == "host":
             destination = lst[id+3] + "/" + mask
          else:
             destination = lst[id+2] + "/" + mask
      else:
        if lst[id] == "any4":
            source = "@ANY"
        elif lst[id] == "any":
            source = "@ANY"
        else:
#            print(id)
#            print(*lst)
            mask = str(IPAddress(lst[id+1]).netmask_bits())
            if lst[id] == "host":
                source = lst[id+1] + "/" + mask
            else:
                source = lst[id] + "/" + mask
        if  lst[id+2] == "object-group":
            destination = ','.join(map(str,nets.get(lst[id+3])))
        elif lst[id+2] == "object":
            destination = "@%s" % lst[id+3]
        else:
            if lst[id+1] == "any4":
               destination = "@ANY"
            elif lst[id] == "any":
               destination = "@ANY"
            else:
               mask = str(IPAddress(lst[id+2]).netmask_bits())
               if lst[id+1] == "host":
                  destination = lst[id+2] + "/" + mask
               else:
                  destination = lst[id+1] + "/" + mask
      
      return source,destination
     except TypeError:
        messagebox.showerror('', 'Ошибка конвертации на строке: %s' % ' '.join(lst))
        vipnet_box.insert('end', '<<<--------------Ошибка-------------->>>\n')


def convert_config():
    global runcount
    runcount += 1
    nets={}
    net=[]
    service_objects={}
    service_object=[]
    object_name_pr=""
    net_name_pr=""
    ports=[]
    rule_name=""
    vipnet_box.delete('1.0', 'end')
#    line = 
    for line in asa_box.get('1.0', 'end').split('\n'):
        error_trig = True
        if ports and not re.search("port-object eq", line):
            result = "firewall service-object add name " + name + ' '.join(ports)                       
            vipnet_box.insert('end', result)
            vipnet_box.insert('end', '\n')
            ports = []
        if re.search("object service", line):
            lst=line.split(' ')
            name = "@%s" % lst[2]
        if re.search("service tcp destination eq", line):
            lst=line.split(' ')
            port = change_asa_service(lst[5])
            error_trig = False          
            result = "firewall service-object add name " + name + " tcp dport " +port
            vipnet_box.insert('end', result)
            vipnet_box.insert('end', '\n')
        if re.search("service udp destination eq", line):
            lst=line.split(' ')
            port = change_asa_service(lst[5])
            error_trig = False 
            result = "firewall service-object add name " + name + " udp dport " +port            
            vipnet_box.insert('end', result)
            vipnet_box.insert('end', '\n')
            
        if re.search("object-group service", line):
            lst=line.split(' ')        
            error_trig = False
            if len(lst) == 4:
                name = "@%s" % lst[2]
                protocol = lst[3].strip()
            else:
                object_name = lst[2]
                service_objects.update({object_name: ""})
                if object_name != object_name_pr:               
                   service_object=[]
                object_name_pr = object_name
        if re.search("service-object", line):
            lst=line.split(' ')
            if lst[2] == "object":
                service_object.append("service @%s" % lst[3])
                service_objects.update({object_name: service_object})
            if lst[3] == "destination":
                port = change_asa_service(lst[5])
#                service_object.append("@%s" % lst[5].upper())
                service_object.append(lst[2] + " dport " + port)
                service_objects.update({object_name: service_object})

        if re.search("port-object eq", line):
            lst=line.split(' ')
            port = change_asa_service(lst[3])
            if  protocol == "tcp":
                ports.append(" tcp dport " + port)
            if  protocol == "udp":
                ports.append(" udp dport " + port)           
            if  protocol == "tcp-udp":
                ports.append(" tcp dport " + port + " udp dport " + port)

            error_trig = False
        if re.search("object network", line):
           lst=line.split(' ')
           name = "@%s" % lst[2]
        if re.search("subnet", line):
           lst=line.split(' ')
           mask = str(IPAddress(lst[3]).netmask_bits())
           result = "firewall ip-object add name " + name + " " + lst[2] + "/" + mask
           vipnet_box.insert('end', result)
           vipnet_box.insert('end', '\n')
        if re.search("host", line):
           lst=line.split(' ')
           if lst[1] == "host":
               result = "firewall ip-object add name " + name + " " + lst[2]
               vipnet_box.insert('end', result)
               vipnet_box.insert('end', '\n')                            
        if re.search("object-group network", line):
           lst=line.split(' ')
           net_name = lst[2]           
           nets.update({net_name: ""})
           if net_name != net_name_pr:               
               net=[]
           net_name_pr = net_name
        if re.search("network-object object", line):
           lst=line.split(' ')
           net.append("@%s" % lst[3])
           nets.update({net_name: net})
#    print(nets)
#    print(nets.get("Subnet_flat_AD"))
#        print(error_trig)
#     except Exception:
#         messagebox.showerror('', 'Ошибка конвертации на строке ')
        if re.search("icmp", line):
            #messagebox.showerror('', 'Обнаружено правило icmp трафика\nВ конфиг vipnet не переносится\n %s' % line)
            continue
        if re.search("interface", line):
            #messagebox.showerror('', 'Обнаружено правило привязанное к интерфейсу ASA\nВ конфиг vipnet не переносится\n %s' % line)
            continue
        if re.search("extended permit esp", line):
            messagebox.showerror('', 'Обнаружено правило esp трафика\nВ конфиг vipnet не переносится\n %s' % line)
            continue
        if re.search("inactive", line):
            rule_name = ""
            messagebox.showerror('', 'Обнаружено отключенное правило\nВ конфиг vipnet не переносится\n %s' % line)
            continue
        if re.search("access-list global_access remark", line):
            lst=line.split('remark')
            rule_name = '"%s"' % lst[1].strip()
            
        if re.search("access-list global_access extended", line):
            lst=line.split(' ')
            if lst[4] == "ip":
                service = "service @any"
                id=5
                source,destination = parse_accesslist(id,lst,nets)
                error_trig = False
            elif lst[3] == "permit" and lst[4] == "object-group":
                if lst[5] in service_objects:
                    service = ' '.join(map(str,service_objects.get(lst[5])))
                else:
                    port = change_asa_service(lst[5])
                    service = 'service @%s' % port
                id=6
                source,destination = parse_accesslist(id,lst,nets)
                error_trig = False
            elif lst[4] == "tcp":
                id=5
                source,destination = parse_accesslist(id,lst,nets)
                if lst[9] == "object-group":                   
                   if lst[10] in service_objects:
                       service = "service " + ','.join(map(str,service_objects.get(lst[10])))
                   else:
                       port = change_asa_service(lst[10])
                       service = 'service @%s' % port
                if lst[8] == "object-group":
                   service = "service " + ','.join(map(str,service_objects.get(lst[9])))
                error_trig = False
            elif lst[4] == "udp":
                id=5
                source,destination = parse_accesslist(id,lst,nets)
                if lst[9] == "object-group":
                   
                   if lst[10] in service_objects:
                       service = "service " + ','.join(map(str,service_objects.get(lst[10])))
                   else:
                       port = change_asa_service(lst[10])
                       service = 'service @%s' % port
                if lst[8] == "object-group":
                   service = "service " + ','.join(map(str,service_objects.get(lst[9])))
                error_trig = False
            else:
                port = change_asa_service(lst[5])
                service = "service @%s" % port
                id=6
                source,destination = parse_accesslist(id,lst,nets)
                error_trig = False
            if  lst[3] == "permit":
                action = "pass"
            else:
                action = "drop"  
            #print(source, destination,service, action)
            #print(rule_name)
            if rule_name != "":
                result = 'firewall forward add rule {name} src {src} dst {dst} {serv} {act}'.format(name=rule_name, src=source, dst=destination, serv=service,act=action)
                rule_name=""
            else:
                result = 'firewall forward add src {src} dst {dst} {serv} {act}'.format(src=source , dst=destination, serv=service,act=action)
            vipnet_box.insert('end', result)
            vipnet_box.insert('end', '\n')
            #print(error_trig)
            if error_trig:
              messagebox.showerror('', 'Ошибка конвертации на строке %s' % ' '.join(lst))
              vipnet_box.insert('end', '<<<--------------Ошибка-------------->>>\n')        
Button(
    window,
    text='КОНВЕРТИРОВАТЬ',
    command=demo_mode
).pack(expand=True)
window.bind("<Button-3>", do_popup)
window.mainloop()
