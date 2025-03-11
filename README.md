# HikvisionZM
###Hikvision ZoneMinder plugin to use in camera motion detection

#####What it does:
 - connects to the zoneminder database looks for all monitors with the specified string "$matchstr" on the end of the name. Default: "_mol-" (so your monitor name in zoneminder would be "mymonitor_mol-") There may be a better way to do this, I'm open to suggestions. 
 - The camera username, password, and IP are pulled from the camera config in zoneminder.
 - The script then connects to each cameras http push stream and waits for a motion event to be sent. The script is threaded so each camera stream is opened in a new thread.
 - If the camera is in Record or Nodect mode, the script enables a forced alarm when an event is received and cancels it after "$alarmdelay" seconds of not receiving any activity. The camera does not send an event end message, so we just have to use this timer to determine when to end the even in zonminder. 
 - NOTE - using this script in Modect or Mocord mode is experimental and has not been tested, do not use this unles you are testing it. If you do test it, please let me know if it works or if adjustments need to be made. If the camera is in Modect or Mocord mode the script runs in hybrid mode and suspends zoneminder motion detection when no events are active on the camera and resumes zoneminder motion detection when events are active on the camera. My theory behind this is to be able to continue to use the advanced features of the zoneminder motion detection and save cpu cycles when nothing is going on. In order for this to work the camera motion detection would need to be configured to detect on the complete frame and set sensitivity to high, then set zoneminder motion detection as usual.  Also the zonminder "MAX_SUSPEND_TIME" config option should be enabled and 30 seconds or more, this is a failsafe in case of a script failure. The script will resuspend 2 seconds before the MAX_SUSPEND_TIME. I haven't tested the Hybrid mode yet and I'm not sure how well it will work.
 - The camera I tested with is the DS-2CD2332-I and it has 5 event types: Line crossing detection, Intrusion detection, Motion Detection, PIR, and Video Tampering. You can set a different score for each type (they must be different) and if more than 1 even is active at the same time, the highest score will show as the active even in zoneminder. If you have all 4 events active at the same time and the highest scored event ends first, then the next highest event will become active and you will see the score in zoneminder change.
 - To run the script in Linux/Unix you must set the permissions on the script to executable: chmod 755 motionstream.pl
 - The script can be run from any directory you would like and should probably be run as the same user that zoneminder runs as.
 - If you manually execute the script in the foreground, you will see it output the IP of the cameras that it connected to (the ones with the match string "_mol-" in the name). When the motion detection type that you configured on the camera is triggered you will see the script output that its starting and stopping the zoneminder events and other info.       
 - This script must be run on the zoneminder server and the following perl modules are required: Time::Piece, threads, ZoneMinder, DBI, LWP::UserAgent. You can use cpan or your distros repo to install them, the cpan command would be: 
 - cpan Time::Piece threads DBI LWP::UserAgent
 - 
 - Note - when configuring motion detection on the camera, the only thing that needs to be enabled is the detection type you want and the schedule. The schedule by default is set to enabled 24x7 when the detection type is enabled, but if you change it then during the disabled times the camera will not send events to the script. 


##### TODO: 
 - - Figure out how to detect a change in monitor mode (Modect, etc). Query sql on a timed interval? Is there a perl function to get this instead of a sql call?
 - - Figure out why event cause in zoneminder is blank when using record mode.
 - - Add options to use use certain camera event types to trigger forced alarms for Modect or Mocord and disable Hybrid mode.
 - Find out what version cameras don't have the /ISAPI in the URL and check the camera version to dynamically set the correct URL.
 - Write init script.


##### Settings:
 - - $alarmdelay #amount of time in seconds we wait before marking the motion event inactive
 - - $matchstr #Find any monitor with "_mol-" in the name. This can be changed to anything you like.
 - - $httptimeout #Amount of time we wait before saying the http stream is timed out in seconds
 - - $httpretry #Amount of time we wait before trying to reconnect to a timeout http stream in seconds
 - - $alarmtypeval{'VMD'} = '100'; #Set the score for the Motion Detection event type here
 - - $alarmtypeval{'shelteralarm'} = '120';   #Set the score for Video Tampering Detection event type here
 - - $alarmtypeval{'fielddetection'} = '140'; #Set the score for Intrusion Detection event type here
 - - $alarmtypeval{'linedetection'} = '150';  #Set the score for the Line crossing detection event type here
 - - $alarmtypeval{'PIR'} = '200';  #Set the score for the IR Motion Detection event type here
 - - my $ISAPI = '/ISAPI'; #In some camera models this is not in the path, set to "my $ISAPI = ''" if the script does not work.
 -  You can test with the following curl command, it does not work try with out the /ISAPI
 -  curl -s -S -N -u username:password http://192.168.1.10/ISAPI/System/time/localTime


##### ZoneMinder Camera Settings (DS-2CD2332-I):
- General Tab
- - Name: Camera1_mol-
- - Source Type: Remote
- Source Tab
- - Remote Protocol: RSTP
- - Remote Method: RTP/RSTP
- - Remote Host Name: user:pass@192.168.1.1
- - Remote Host Port:554
- - Remote Host Path: /Streaming/Channels/1
- - Target Colorspace: 24 bit	
- - Capture Width (pixels): 1920
- - Capture Height (pixels): 1080

NOTE - If your camera will only work with FFMpeg, the code now checks for the FFMpeg setting and pulls the username and password from the Path field. The Path format should be: rtsp://username:password@192.168.1.10:554/Streaming/Channels/1

##### Monit:
For starting and stopping the script, I use monit. It also does a good job for ZM and mysql.
I use the following settings in my /etc/monit/monitrc:

```
 check process mysql with pidfile /var/run/mysqld/mysqld.pid
     start program = "/etc/init.d/mysql start"
     stop program = "/etc/init.d/mysql stop"
     if changed PID then exec "/etc/init.d/zoneminder restart"

 check process zoneminder with pidfile /var/run/zm/zm.pid
    start program = "/etc/init.d/zoneminder start"
    stop program  = "/etc/init.d/zoneminder stop"
    depends on mysql
    if changed PID then exec "/usr/bin/killall motionstream.pl; /home/wayne/motionstream.pl&"

 check process motionstream with pidfile /var/run/motionstream.pid
    start program = "/home/wayne/motionstream.pl&" with timeout 60 seconds
    stop program  = "/usr/bin/killall motionstream.pl"
    depends on zoneminder
```
