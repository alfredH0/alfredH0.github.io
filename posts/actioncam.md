# Reverse engineering cheap action camera

## How to get the live preview of an action camera on pc


The main objective is to connect the camera to my home wifi network and get the preview of the camera to the pc. This types of cameras have their own wifi module and comes with a variety of android apps that allows control and see the camera in real time.

This work is mostly inspired by Jonas Köritz, in his [blog](https://blog.jonaskoeritz.de/2017/02/21/hacking-the-xpro2-action-camera/) he does the same process as mentioned here, however he utilizes Node.js and Go and encapsulates the video on RTP packets. Jonas job was fundamental for this project, specifically the use of the wpa_supplicant.conf file and analyzing the payload of the UDP packets. Thanks Jonas!

## Part One: capturing traffic

One of the first things that caught my attention about the camera was the live preview in the application, so i started investigating how it works. My first idea was trying to reverse engineering the app using a program called JADX, the program allows to decompile apk files, after running it, i could see parts of the code and things like the androidmanifest file, but since i don't know any java the plan was discarded (If you know how to reverse engineer apps you can try this method and share how exactly does the "official" apps plays the stream).

I did a fast search on google looking for someone who tried to get the stream and found this [forum](https://dashcamtalk.com/forum/threads/hacking-q3h-allwinner-v3-camdroid.20507/page-18), there were a couple guys trying to do this, here is where i found the link to the Jonas blog. The forum is about Allwinner v3 cameras, there are a lot of different manufacturers but all are based on the allwinner chip, a guy named [Petesimon](https://dashcamtalk.com/forum/members/petesimon.31973/) made a very useful program that allows for firmware backup of the cameras (its recommended you do a backup before messing with the cam), you can see his video [here](https://www.youtube.com/watch?v=QrhPxpFFMrc). 

The guys on the forum were trying to analyze the network traffic between the camera and the app, you can do this with different methods, one is connecting the pc to the camera wifi and use wireshark to sniff the packets between the app on a physical android device and the camera. Another way is to use an app that let us analyze traffic on the android phone, like tcpdump. I tried both of these methods but there was missing packets or weird stuff on the final capture. 

I decided to download Genymotion, which is an android emulator for pc, run the camera app there, and capture traffic on the same pc with wireshark. This wont work right away, first you have to switch genymotion hypervisor to virtualbox and set the network mode to Bridge. After that connect the computer to the camera wifi and create the virtual device, open wireshark and capture the traffic between the emulator and the camera. You can use a filter like this `ip.src == 192.168.100.1 || ip.src == 192.168.100.167` on wireshark to only see the communication between the cam and the pc, generally this cameras have the same ip `192.168.100.1`, but the pc ip is going to be different. You will get something like this 

![](/assets/actioncam/wire1.webp)
_Wireshark capture_

## Part Two: analyzing data

The key to analyze the data is identify patterns. Every time we run the app we see some tcp packets being sent to the camera and then a stream of UDP packets begins. If you look at those tcp packets you will find something interesting

![](/assets/actioncam/login.webp)
_Login packet_

This packets contain some kind of login information with an user `admin` and a password `12345`, if you also look at the data structure you will see a pattern that repeats in other packets, they start with the bytes `0xAB 0xCD`, then two bytes for the length of the payload and finally four bytes for a command, that tells the camera what to do. Thankfully Jonas already did this in his blog, i only need the login and begin stream commands, if you need other commands check his site.

The UDP packets contain h264 data in the payload and follows a similar structure as the tcp packets. To be able to play this we need to remove the unnecessary protocol bytes, and get the raw h264 data that is being send into nal units. You will see a bunch of 1008 bytes length packets in between of 24 bytes length packets (there is one extra packet with variable length that contain the final part of every chunk of data), the bytes following the protocol on the first packet of every chunk, are the start of a nal unit `0x00 0x00 0x00 0x01` that contains the video information, so you need to send that to ffplay or gstreamer

![](/assets/actioncam/wire2.webp)
_UDP stream_

## Part Three: code

I wanted to write the code myself but looking at the comments in Jonas blog i found a guy named "nonzod" who did a python code, here is the [link](https://github.com/nonzod/XproHacks) to his github page, i did a couple modifications, here is the final code

```python
import socket
import threading
import signal
import sys
import struct

host = '192.168.1.30' # Camera ip address
port = 6666

controlSocket = socket.socket() 

for i in range(20):
    try: 
        controlSocket.connect((host, port))
        print("Camera found on ip " + host)
        break
    except:
        a=str(int(host[10:12])+1)
        host=host[0:10]+a

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.168.1.38", 6840)) # Pc ip address

proxySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

response = ''

def login():
    controlSocket.send(struct.pack('>8s64s64s', b'\xAB\xCD\x00\x81\x00\x00\x01\x10', b'admin', b'12345'))
    response = controlSocket.recv(1024)
    controlSocket.send(b'\xAB\xCD\x00\x00\x00\x00\x01\x13')
    response = controlSocket.recv(1024)

def start_video_stream():
    controlSocket.send(b'\xAB\xCD\x00\x08\x00\x00\x01\xFF')
    controlSocket.send(b'\xAB\xCD\x00\x00\x00\x00\x01\x12')
    response = controlSocket.recv(1024)

def ping():
    controlSocket.send(b'\xAB\xCD\x00\x00\x00\x00\x01\x12')
    __response = controlSocket.recv(1024)
    threading.Timer(10, ping).start()

def listen():
    print("Sending video")
    while True:
        signal.signal(signal.SIGINT, exit)
        recvpack, payload = sock.recvfrom(1024)
        control = recvpack[7]
        if control == 1:
            proxySocket.sendto(recvpack[8:], ('127.0.0.1', 8888))

def exit(signal, frame):
    print('Bye!')
    sys.exit(0)
            
login()
start_video_stream()
ping()
listen()
```
I added a try except block for searching the camera ip, if it is unknown, but only works if other devices on the network don't accept the socket connection, also is very slow. The code logins in the cam and sends the necessary packets to start the live preview, then receives an UDP packet, and removes the first 8 bytes before sending it to the local network on port 8888. You can play that using gstreamer or ffplay with these commands respectively

```bash
gst-launch-1.0 -v udpsrc port=8888 ! h264parse ! avdec_h264 ! xvimagesink sync=false
ffplay -fflags nobuffer -flags low_delay -probesize 32 -analyzeduration 1 -strict experimental -framedrop -vf setpts=0 udp://@:8888
```
## Part Four: connect to router

First you need to create a file named wpa_supplicant.conf, check Jonas [blog](https://blog.jonaskoeritz.de/2017/02/21/hacking-the-xpro2-action-camera/) for more information on how to do this. This method of connecting to network using a file is also used in raspberry pi boards and linux systems, that's because these cameras run a version of android, so if you encounter some problems you can search for other systems. We can access the camera using ADB, make sure the camera is detected using ADB devices,
```bash
adb devices
```
First we need to push the file with
```bash
adb push '{wpa_supplicant file directory}' '/data/misc/wifi/'
```
The network interface on the camera is wlan0, if you press the wifi button on the cam it will start the host mode, to check the network status connect to the camera shell and use
```bash
adb shell
iwconfig
```
![](/assets/actioncam/iwconfig.webp)
_iwconfig command_

in my case ifconfig doesn't work, but since is an android/linux system you can see the available commands in the /system/bin directory
```bash
cd /system/bin
ls
```
If we execute iwconfig we see that wlan0 is not associated with any wifi, to use the file execute the following commands
```bash
wpa_supplicant -c /data/misc/wifi/wpa_supplicant.conf -i wlan0 -B -D nl80211
dhcpcd wlan0
```
Then run the iwconfig again and you will see that the camera is connected and the name of your network 

![](/assets/actioncam/conected.webp)
_iwconfig command_

The connection will last while the camera is powered on, but if you restart it, you will have to manually connect it again, i tried to find a solution like modifying wpa_supplicant.conf from other directories or modifying the init.rc file but i couldn't get it to work, mostly because there are read-only directories and when the camera restarts some files are deleted or restored. 

If you look at .rc files on the root directory you can find interesting things, for example, when i turn my camera on, it makes a sound, you can see were the sound file its located, if you go to `/system/res/others/`. There is also stuff from the GUI like images and sounds. 

## Final Toughts

Now that we have a live preview of the camera on the pc, you can pipeline Gstreamer on opencv and run your computer vision code, have in mind that the quality of the live preview is not the full quality of the sensor. I've also seen people that modify the camera to attach their own lenses, or maybe you can add heat dissipation or use a bigger battery.

![](/assets/actioncam/live1.webp)
![](/assets/actioncam/live2.webp)


        












