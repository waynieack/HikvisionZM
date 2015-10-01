# HikvisionZM
Hikvision ZoneMinder plugin to use in camera motion detection

What it does:
 - connects to the zoneminder database looks for all monitors with the specified string "$matchstr" on the end of the name. Default: "_mol-" (so your monitor name would be "mymonitor_mol-") There may be a better way to do this, I'm open to suggestions. 
 - The camera username and password are pulled from the "remote hostname" section of the camera config in zonminder IE: user:pass@192.168.1.10  
 - The script then connects to each cameras http push stream and waits for a motion event to be sent. The script is threaded so each camera stream is opened in a new thread. I only tested with 1 camera, so multicamera needs to be tested.
 - If the camera is in Record or Nodect mode, the script enables a forced alarm when an event is recieved and cancels it after "$alarmdelay" seconds of not receiving any activity. The camera does not send an event end message, so we just have to use this timer to determine when to end the even in zonminder. 
 - If the camera is in Modect or Mocord mode the script runs in hybrid mode and suspends zoneminder motion detection when no events are active on the camera and resumes zoneminder motion detection when events are active on the camera. My theory behind this is to be able to continue to use the advanced features of the zoneminder motion detection and save cpu cycles when nothing is going on. In order for this to work the camera motion detection would need to be configured to detect on the complete frame and set sensitivity to high, then set zonminder motion detection as usual.  Also the zonminder "MAX_SUSPEND_TIME" config option should be enabled and 30 seconds or more, this is a failsafe in case of a script failure. The script will resuspend 2 seconds before the MAX_SUSPEND_TIME. I haven't tested the Hybrid mode yet and I'm not sure how well it will work.
 - The camera I tested with is the DS-2CD2332-I and it has 4 event types: Line crossing detection, Intrusion detection, Motion Detection, and Video Tampering. You can set a different score for each type (they must be different) and if more than 1 even is active at the same time, the highest score will show as the active even in zoneminder. If you have all 4 events active at the same time and the highest scored event ends first, then the next highest event will become active and you will see the score in zoneminder change.
 - This script must be run on the zoneminder server and the following perl modules are required: Time::Piece, threads, ZoneMinder, DBI, LWP::UserAgent.
 - TODO: 
 - - Add Video Tampering and Intrusion detection event types. 
 - - Figure out a good way to start and stop the script with zoneminder.
 - - Test multi camera. 
 - - Figure out how to detect a change in monitor mode (Modect, etc). Query sql on a timed interval? Is there a perl function to get this instead of a sql call?
 - - Figure out why event cause in zonminder is blank when using record mode.
 - - Add options to use use certain camera event types to trigger forced alarms for Modect or Mocord and disable Hybrid mode. 

Settings:
 - - $alarmdelay #amount of time in seconds we wait before marking the motion event inactive
 - - $matchstr #Find any monitor with "_mol-" in the name
 - - $httptimeout #Amount of time we wait before saying the http stream is timed out in seconds
 - - $httpretry #Amount of time we wait before trying to reconnect to a timeout http stream in seconds
 - - $alarmtypeval{'VMD'} = '100'; #Set the score for the Motion Detection event type here
 - - $alarmtypeval{'linedetection'} = '150'; #Set the score for the Line crossing detection event type here

ZoneMinder Camera Settings (DS-2CD2332-I):
General Tab
- Name: Camera1_mol-
- Source Type: Remote
- Source Tab
- Remote Protocol: RSTP
- Remote Method: RTP/RSTP
- Remote Host Name: user:pass@192.168.1.1
- Remote Host Port:554
- Remote Host Path: /Streaming/Channels/1
- Target Colorspace: 24 bit	
- Capture Width (pixels): 1920
- Capture Height (pixels): 1080
