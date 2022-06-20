from Tkinter import *
import Tkinter as tk
import ttk
from arp_spoof import *
from DNS import * 
import socket
from multiprocessing import Process
import sys

# When Help button is pressed launch Help Pop-up
def launchHELP(base_window):
    print("Launch Help")
    top = Toplevel(base_window, width=100, height=10)    
    top.geometry("300x180")
    top.title("Help Page")

    #canvas = Canvas(top, width=300, height=180)  #create Canvas to print the text for help page
    #canvas.create_text(30, 20, text="Introduce Your IP (can be found using the command \'ifconfig\' on Linux, the Target's IP from your Local Area Network and the Host's IP / Gateway IP. Then, click on the desired attack. You can stop the attack at any time using the button 'STOP'. You can exit the application using the button 'EXIT'.")
    
    my_label = Label(top, width=300, height=180, text="Introduce Your IP (can be found using the\n command \'ifconfig\' on Linux, the Target's IP\n from your Local Area Network and the Host's\nIP / Gateway IP. Then, click on the desired\n attack. You can stop the attack at any time\nusing the button 'STOP'. You can exit the\n application using the button 'EXIT'. SvRedirect\n is used only for DNS, represents the IP to\n redirect the Target.")
    my_label.pack(pady=0)
    
# When the ARP Attack button is pressed launch the ARP attack
def launchARP(ipAttacker_entry, ipTarget_entry, ipHost_entry, toPrint):
    ipAttacker = ipAttacker_entry.get()
    ipTarget = ipTarget_entry.get() 
    ipHost = ipHost_entry.get() 
    
    global processARP
    processARP = Process(target=startARP, args=(ipAttacker, ipTarget, ipHost, toPrint))
    processARP.start()   #start ARP attack process

# When the DNS Attack button is pressed launch the DNS attack
def launchDNS(ipAttacker_entry, ipTarget_entry, ipHost_entry, toPrint, servRed_entry):
    ipAttacker = ipAttacker_entry.get()
    ipTarget = ipTarget_entry.get() 
    ipHost = ipHost_entry.get() 
    servRed = servRed_entry.get()

    global processARP  #we need to be man-in-the-middle to execute DNS Attack, hence use ARP Attack first
    processARP = Process(target=startARP, args=(ipAttacker, ipTarget, ipHost, toPrint))
    processARP.start() #start ARP attack process

    global processDNS
    processDNS = Process(target=startDNS, args=(servRed,))
    processDNS.start() #start DNS attack process

# When the Stop button is pressed, stop the current attack if there is one active
def stop():
    #ipAttacker = ipAttacker_entry.get()
    #ipTarget = ipTarget_entry.get() 
    #ipHost = ipHost_entry.get() 

    doingNothing = 0  #a useless variable used only because except must exist and not be empty

    print("The attack has stopped.")
    try:
        if processARP.is_alive(): #if ARP process is alive, terminate it
            processARP.terminate()
            #restore(ipTarget,ipHost,0)
            #restore(ipHost,ipTarget,0)
    except:
        doingNothing=1
    try:
        if processDNS.is_alive(): #if DNS process is alive, terminate it
            processDNS.terminate()
    except:
        doingNothing=1

# When the Exit button is pressed, stop the current attack if there is one active and exit the app
def exit():
    stop()
    sys.exit()
    
    
def main():
    #create base window and tabsystem
    base_window = Tk()
    base_window.title("Tool for Ethical Hacking")
    tabsystem = ttk.Notebook(base_window)

    #ipattacker
    frame_ipAt = Frame(base_window)
    frame_ipAt.pack()
    ipAttacker_label = Label(frame_ipAt, text="Your IP:")
    ipAttacker_label.pack(side=tk.LEFT)
    ipAttacker_entry = Entry(frame_ipAt, width=41)
    ipAttacker_entry.pack(side=tk.RIGHT)

    #iptarget
    frame_ipTa = Frame(base_window)
    frame_ipTa.pack()
    ipTarget_label = Label(frame_ipTa, text="Target's IP:")
    ipTarget_label.pack(side=tk.LEFT)
    ipTarget_entry = Entry(frame_ipTa, width=38)
    ipTarget_entry.pack(side=tk.RIGHT)

    #iphost
    frame_ipHo = Frame(base_window)
    frame_ipHo.pack()
    ipHost_label = Label(frame_ipHo, text="Host's IP:")
    ipHost_label.pack(side=tk.LEFT)
    ipHost_entry = Entry(frame_ipHo, width=40)
    ipHost_entry.pack(side=tk.RIGHT)

    #myServer
    frame_servRed = Frame(base_window)
    frame_servRed.pack()
    servRed_label = Label(frame_servRed, text="SvRedirect:")
    servRed_label.pack(side=tk.LEFT)
    servRed_entry = Entry(frame_servRed, width=38)
    servRed_entry.pack(side=tk.RIGHT)

    toPrint = IntVar()
    checkButtonPrint = Checkbutton(base_window, text="Print commands in cmd", variable=toPrint)
    checkButtonPrint.pack()

    frameTop = Frame(base_window)
    
    #Create buttons with their onClick commands
    buttonARP = Button(frameTop,text="ARP attack", command=lambda:launchARP(ipAttacker_entry, ipTarget_entry, ipHost_entry, toPrint))
    buttonDNS = Button(frameTop,text="DNS attack", command=lambda:launchDNS(ipAttacker_entry, ipTarget_entry, ipHost_entry, toPrint, servRed_entry))
    buttonSSL = Button(frameTop,text="SSL attack")
    buttonHELP = Button(base_window,text="HELP", width=30, command=lambda:launchHELP(base_window))
    buttonSTOP = Button(base_window, text="STOP", width=30, command=lambda:stop())
    buttonEXIT = Button(base_window, text="EXIT", width=30, command=lambda:exit())
    
    #Draw the buttons
    buttonARP.pack(side = LEFT, padx=5, anchor=NW)
    buttonDNS.pack(side = LEFT, padx=5)
    buttonSSL.pack(side = LEFT, anchor = NE)
    frameTop.pack()
    buttonHELP.pack()
    buttonSTOP.pack()
    buttonEXIT.pack()

    try:
        base_window.mainloop()
    except KeyboardInterrupt:
        print("EXITING")



if __name__ == '__main__':
    main()









