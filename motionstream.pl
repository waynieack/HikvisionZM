#!/usr/bin/perl
#use strict;
use warnings;
use Time::Piece;
use threads;
use ZoneMinder;
use DBI;
use LWP::UserAgent;
use Fcntl ':flock';
#use Data::Dumper;

# Version 1.3.0
use constant MONITOR_RELOAD_INTERVAL => 300;

my $alarmdelay = 30; #amount of time in seconds we wait before marking the motion event inactive
my $matchstr = '_mol-'; #Find any monitor with "_mol-" in the name. This can be changed to anything you like.
my $httptimeout = 40; #Amount of time we wait before saying the http stream is timed out in seconds
my $httpretry = 30; #Amount of time we wait before trying to reconnect to a timeout http stream in seconds
my $PidPath = "/var/run/motionstream.pid"; #Create pid file so only 1 instance can run
my $LogPath = "/var/log/";
my $ISAPI = '/ISAPI'; #In some camera models this is not in the path, set to "my $ISAPI = ''" if the script does not work.
# You can test with the following curl command, it does not work try with out the /ISAPI
# curl -s -S -N -u username:password http://192.168.1.10/ISAPI/System/time/localTime



my $CamTypeMap;

# Set zoneminder score for Hikvision detection types
$CamTypeMap->{'HikVision'}->{'alarmtypeval'}->{'VMD'} = '100';            # Motion Detection
$CamTypeMap->{'HikVision'}->{'alarmtypeval'}->{'shelteralarm'} = '120';   # Video Tampering
$CamTypeMap->{'HikVision'}->{'alarmtypeval'}->{'fielddetection'} = '140'; # Intrusion Detection
$CamTypeMap->{'HikVision'}->{'alarmtypeval'}->{'linedetection'} = '150';  # Line Crossing Detection
$CamTypeMap->{'HikVision'}->{'alarmtypeval'}->{'PIR'} = '200';            # IR Motion Detection

# Set the URL for Hikvision stream
$CamTypeMap->{'HikVision'}->{'URL'} = $ISAPI.'/Event/notification/alertStream';

# Set the URL to get the current time from Hikvision cameras
$CamTypeMap->{'HikVision'}->{'timer'} = $ISAPI.'/System/time/localTime';


# Set zoneminder score for DoorBird detection types
$CamTypeMap->{'DoorBird'}->{'alarmtypeval'}->{'motionsensor'} = '100';   # IR Motion Detection
$CamTypeMap->{'DoorBird'}->{'alarmtypeval'}->{'keypad'} = '150';         # Keypad Press (not supported on all models)
$CamTypeMap->{'DoorBird'}->{'alarmtypeval'}->{'rfid'} = '175';           # RFID (not supported on all models)
$CamTypeMap->{'DoorBird'}->{'alarmtypeval'}->{'doorbell'} = '200';       # DoorBell Press 

# Set the URL for DoorBird stream. 
# NOTE! You must include the detection types that you want to use in this url. !
$CamTypeMap->{'DoorBird'}->{'URL'} = '/bha-api/monitor.cgi?ring=doorbell,motionsensor';

# Doorbird doesn't send the event time in the stream, so we have to use the local time.
$CamTypeMap->{'DoorBird'}->{'timer'} = 'local';


my %alarm;
my %monitors;
my %rcvbuf;
my %params;


open( LH, '>', $PidPath ) or die "Can't open $PidPath for locking!\nError: $!\n";
 # lock file so that it can only be accessed
 # by the current running script
flock LH, LOCK_EX|LOCK_NB
or die "$PidPath is already running somewhere!\n$!";
print LH $$;


&loadMonitors;
&startthreads;

sub startthreads {
	my @threads;
    foreach my $ip ( keys %{$monitors} ) { 
       #open($monitors->{$ip}->{'FH'}, '>>', $LogPath."motionstream-$ip.log");
       push @threads, async { (\&startstream($monitors->{$ip}->{'CREDS'},$ip)) };
    }
    foreach (@threads) {
       $_->join();
    }
}



sub startstream {
	my ($creds, $ip) = @_;
	my $thr = threads->self(); 
	my $tid = $thr->tid;


	# $|=1; # autoflush
	#  my $FH = $monitors->{$ip}->{'FH'};
	#  open(FH, '>>', $LogPath."motionstream-$ip.log")
	#	or warn "Cannot open $files: $OS_ERROR";
	#  print FH "Starting thread $tid for IP $ip\n"
	#	or warn "Cannot write to $files: $OS_ERROR";

 	warn scalar(localtime)." - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - Starting thread $tid\n";
	$alarm->{$tid} = $ip;
	&cameraconnect($creds,$ip,$tid);
}


sub cameraconnect { 
	my ($creds, $ip, $tid) = @_;
	my $ua = LWP::UserAgent->new();
 	$ua->timeout($httptimeout);
	my $Manufacturer = $monitors->{$ip}->{'HASH'}->{Manufacturer};
	my $URL = $CamTypeMap->{$Manufacturer}->{'URL'};
	
	#warn "$ip - ".scalar(localtime).' - Connecting to URL: http://'.$creds.'@'.$ip.$URL."\n";

 	my $req = $ua->get('http://'.$creds.'@'.$ip.$URL,
                       ':content_cb' => \&ReadStream,
                       ':read_size_hint' => 540,);

  	if ($req->code) {
        	warn scalar(localtime)." - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - timed out! - HTTPCode: ". $req->code ." -- Retrying\n";
        	$rcvbuf->{$tid} = '';
        	sleep $httpretry;
        	&cameraconnect($monitors->{$ip}->{'CREDS'},$ip,$tid);
  	}
}

sub ReadStream {
	my($msg, $response) = @_;
	
	my $thr = threads->self(); my $tid = $thr->tid;
	my $ip = $alarm->{$tid};
	$msg = $rcvbuf->{$tid}.$msg if (defined $rcvbuf->{$tid}); #add the buffer to the start of the message
	$rcvbuf->{$tid} = ''; my $Chunk = '';
	my $Manufacturer = $monitors->{$ip}->{'HASH'}->{Manufacturer};
	
	
	if ($Manufacturer eq 'DoorBird') {
		while (1) {
			if ( $msg  =~ m/--ioboundary\r\nContent-Type: text\/plain\r\n\r\n(.*?)\r\n\r\n(.*)/s ) {
				$Chunk = "$1"; 
				#print $Chunk;
				$msg = $2; #grab whats left after the full message
							#to see if its a full message on the next loop
							#or save it to the buffer
				foreach my $eventype ( keys %{$CamTypeMap->{$Manufacturer}->{'alarmtypeval'}} ) {
					
					if ( $Chunk =~ m/$eventype:H/) {
						#print "$Manufacturer - $Chunk\n";
						unless (exists $alarm->{$tid}->{$ip}->{$eventype}->{'isActive'}) { 
							&activatezmalarm($ip, $eventype); 
						} elsif (!$alarm->{$tid}->{$ip}->{$eventype}->{'isActive'}) { 
							&activatezmalarm($ip, $eventype);
						}
						$alarm->{$tid}->{$ip}->{$eventype}->{'dateTime'} = time();
		
						#print "-----------------------\n";
						#print $alarm->{$tid}->{$ip}->{'VMD'}->{"dateTime"}."-- VMD -- Active\n";
						#print "-----------------------\n";
					}
				}
				if (!length($msg)) { last }
			} else {
				$rcvbuf->{$tid} = $msg;  # save to buffer hash
				last;
			}		
		}
	} elsif ($Manufacturer eq 'HikVision') {
		while (1) {
			if ( $msg  =~ m/(<ipAddress>)(.*?)--boundary(.*)/s ) {
				$Chunk = "$1$2"; 
				#print $Chunk;
				$msg = $3; #grab whats left after the full message
						#to see if its a full message on the next loop
						#or save it to the buffer
				foreach my $eventype ( keys %{$CamTypeMap->{$Manufacturer}->{'alarmtypeval'}} ) {
					
					$eventype = '<eventType>'.$eventype.'<'; 
					if ( $Chunk =~ m/$eventype/) {
						#print "$Manufacturer - $Chunk\n";
						&inserthash($Chunk, $ip);
						#print "-----------------------\n";
						#print $alarm->{$tid}->{$ip}->{'VMD'}->{"dateTime"}."-- VMD -- Active\n";
						#print "-----------------------\n";
					}
				}
				if (!length($msg)) { last } 
			} else {
				$rcvbuf->{$tid} = $msg;  # save to buffer hash
				last;   
			}
		}
	}
	&checkforinactive($ip) if (defined $ip);
}


sub inserthash {
	my ($rcvbuf, $ip) = @_; 
	my $eventType;
	my $thr = threads->self(); 
	my $tid = $thr->tid; 
	if ($rcvbuf =~ m/<ipAddress>(.*)</) {
		#$ip = $1;
		if ($rcvbuf =~ m/<eventType>(.*)</) { 
			$eventType = $1; 
			#unless (exists $alarm->{$tid}->{$ip}) { $alarm->{$tid} = $ip }
			#if ($rcvbuf =~ m/<activePostCount>(.*)</) {
			#  $alarm->{$tid}->{$ip}->{$eventType}->{"activePostCount"} = $1;
			# }
		
			if ($rcvbuf =~ m/<dateTime>(.*)</) {
				unless (exists $alarm->{$tid}->{$ip}->{$eventType}->{'isActive'}) { 
					&activatezmalarm($ip, $eventType);
				} elsif (!$alarm->{$tid}->{$ip}->{$eventType}->{'isActive'}) { 
					&activatezmalarm($ip, $eventType);
				}
				
				$alarm->{$tid}->{$ip}->{$eventType}->{'dateTime'} = $1;
			}
			
			return 1;
		}
	}
}

sub activatezmalarm {
	my ($ip, $type) = @_;
	my $time = scalar(localtime);
	my $thr = threads->self(); 
	my $tid = $thr->tid;
	my $function = $monitors->{$ip}->{'FUNCT'};
	&validatemem($ip);
	if ( !zmIsAlarmed( $monitors->{$ip}->{'HASH'} ) and ($function eq 'Record' or $function eq 'Nodect') ) {
		zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
		zmTriggerEventOn( $monitors->{$ip}->{'HASH'}, &alarmtypeval($ip,$type), 'Motion', $type );
		warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - triggered by $type\n";
		$alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
		return 1;
	}
	my ( $AlarmScore, $AlarmCause ) = zmMemRead( $monitors->{$ip}->{'HASH'}, [ "trigger_data:trigger_score", "trigger_data:trigger_cause" ] );
		if ((&alarmtypeval($ip,$type) > $AlarmScore) and ($function eq 'Record' or $function eq 'Nodect')) {
			zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
			zmTriggerEventOn( $monitors->{$ip}->{'HASH'}, &alarmtypeval($ip,$type), 'Motion', $type );
			$alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
			warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - updated by $type \n";
			return 1;
		}
	if ($function eq 'Modect' or $function eq 'Mocord') {
		zmMonitorResume( $monitors->{$ip}->{'HASH'} );
		warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - resumed by $type \n";
		$alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
		return 1;
	}
	
    $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
}


 sub checkforinactive {
	my ($ip) = @_;
	my $function = $monitors->{$ip}->{'FUNCT'};
	my $time = scalar(localtime);
	my $thr = threads->self(); my $tid = $thr->tid;
    foreach my $type ( keys %{$alarm->{$tid}->{$ip}} ) {
		my $skipchk = &skipcheck($ip ,$type);
		if ($skipchk eq 1) {
			#warn "CHecking $tid -> $ip -> $type -> dateTime for activity\n";                 
            if (&isAlarmInactive($ip,$alarm->{$tid}->{$ip}->{$type}->{'dateTime'})) {
				warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - Disabling Thread:$tid -> IP:$ip -> Type:$type -> dateTime due to inactivity\n";
                &disablezmalarm($ip, $type); #disable zoneminder alert
            }
		} elsif ($skipchk eq 2) {
			&disablezmalarm($ip, $type);
		}   
    }
	
   #We have to free the memory handle so they don't constantly grow
   #print "last reload time ".$monitors->{$ip}->{lastReload}."\n";
   if (exists $monitors->{$ip}->{lastReload} ) { 
		my $lastreload = $monitors->{$ip}->{lastReload};
		if ( defined($lastreload) ) { 
			if ( ( time() - $lastreload ) > MONITOR_RELOAD_INTERVAL ) {
				&validatemem($ip);
			}
		}
	} else { 
		$monitors->{$ip}->{lastReload} = time();
	}
}


sub skipcheck {
	my ($ip, $type) = @_;
	my $function = $monitors->{$ip}->{'FUNCT'};
	my $thr = threads->self(); 
	my $tid = $thr->tid;

	if ( $function eq 'Modect' or $function eq 'Mocord' ) {
		if (!$alarm->{$tid}->{$ip}->{$type}->{"isActive"} ) { 
			if (!$params->{'SUS_TM'}) { return 0 }
			return 2;
		}   
	}
	
   unless (exists $alarm->{$tid}->{$ip}->{$type}->{'dateTime'}) {
		return 0;
	}
	
    unless (exists $alarm->{$tid}->{$ip}->{$type}->{'dateTime'}->{chktime}) {
		$alarm->{$tid}->{$ip}->{$type}->{'dateTime'}->{chktime} = time;
		return 1;
    }
     
	if ($alarm->{$tid}->{$ip}->{$type}->{'dateTime'}->{chktime} eq time) { 
		return 0;
	} else { 
		return 1;
	}
}  
         
  
 sub checkforactivecount {
  my ($ip) = @_;
  my @ret;
  my $time = scalar(localtime);
  my $thr = threads->self(); 
  my $tid = $thr->tid;
	foreach my $type ( keys %{$alarm->{$tid}->{$ip}} ) {
		if (exists $alarm->{$tid}->{$ip}->{$type}->{'isActive'}) {
			if ( $alarm->{$tid}->{$ip}->{$type}->{'isActive'} ) {
				warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - Current Active Alarm Type:$type\n";
				push (@ret, $type);
			}
		}
	}
	return @ret;
}


sub alarmtypeval {
	my ($ip, $type) = @_;
	my $Manufacturer = $monitors->{$ip}->{'HASH'}->{Manufacturer};
	return $CamTypeMap->{$Manufacturer}->{'alarmtypeval'}->{$type};
}


sub disablezmalarm {
	my ($ip, $type) = @_;
	my $pname = "";
	my $thr = threads->self(); 
	my $tid = $thr->tid;
	my @activetype = &checkforactivecount($ip);
	my $function = $monitors->{$ip}->{'FUNCT'};
	my $activecount = scalar @activetype;
	my $time = scalar(localtime);
	warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - Current Active Alarm Count:$activecount\n";
	&validatemem($ip);

	if ( $function eq 'Modect' or $function eq 'Mocord' ) { #need to figure out how to check if the monitor is suspended, get auto resume time
        if ($activecount > 1) {
            warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - suspended\n";
            delete $alarm->{$tid}->{$ip}->{$type}; #just delete the active alarm from the hash because we have other active ones
            return 1;
        }
		  
        if ($activecount eq 1) {
            $monitors->{$ip}->{'RESUS'} = ($params->{'SUS_TM'} + time) - 2;
            zmMonitorSuspend( $monitors->{$ip}->{'HASH'} ); #suspend the ZM motion detection because our camera motion event cleared
            warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - suspended\n";
            $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 0; #clear the active flag
			#delete $alarm->{$tid}->{$ip}->{$type}->{'dateTime'}; #delete the date so we dont continue to check it
            return 1;
        }
		  
        if (time >= $monitors->{$ip}->{'RESUS'} ) {
			$monitors->{$ip}->{'RESUS'} = ($params->{'SUS_TM'} + time) - 2; # set the resume time, adding the ZM configured time to the current time
			zmMonitorSuspend( $monitors->{$ip}->{'HASH'} ); #resuspend the ZM motion detection due to the ZM auto resume feature 
			warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - REsuspended\n";
			return 1;
        }
	}


	if ( ($function eq 'Record' or $function eq 'Nodect') and (zmIsAlarmed($monitors->{$ip}->{'HASH'}) and $activecount eq 1) ) {
		#zmTriggerEventOff( $monitors->{$ip}->{'HASH'} );
		zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
		warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip, Type:$type - disabled\n";
		delete $alarm->{$tid}->{$ip}->{$type};
		return 1;
	}


	if ( ($function eq 'Record' or $function eq 'Nodect') and (zmIsAlarmed($monitors->{$ip}->{'HASH'}) and $activecount > 1) ) {
		foreach my $name (@activetype) {
			if ($name eq $type) { next } 
			if ($pname eq "") {$pname = $name; next;}
			if (&alarmtypeval($ip,$name) > &alarmtypeval($ip,$pname)) { $pname = $name }
		}

	    if (!$pname eq "" ) { 
			zmTriggerEventOn($monitors->{$ip}->{'HASH'}, &alarmtypeval($ip,$pname), 'Motion', $pname );  
			warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip, Type:$type - key deleted (ZM alarm is still active due to another alarm)\n";
			delete $alarm->{$tid}->{$ip}->{$type};
			return 1;
		}
	}

	delete $alarm->{$tid}->{$ip}->{$type};
}


sub validatemem {
   my ($ip) = @_;
   my $time = scalar(localtime);
   unless (defined ($ip)) { warn "$time - Error: Something went wrong in validatemem, IP is not defined."; return }
   unless (exists $monitors->{$ip}->{'HASH'}) { warn "$time - IP:$ip - Error: Something went wrong in validatemem, \$monitors->\{$ip\}->\{\'HASH\'\} is not defined"; return }
   unless (exists $monitors->{$ip}->{'HASH'}->{Id}) { warn "$time - IP:$ip - Error: Something went wrong in validatemem, \$monitors->\{$ip\}->\{\'HASH\'\}->\{\'Id\'\} is not defined"; return }
   $monitors->{$ip}->{lastReload} = time();
   #my $mr = zmMemRead($monitors->{$ip}->{'HASH'}, "shared_data:valid");
   
   my $mr = zmMemVerify($monitors->{$ip}->{'HASH'});
   $mr = 0 unless (defined($mr)); 
   warn "$time - Monitor:".$monitors->{$ip}->{'HASH'}->{Id}.", IP:$ip - MemReadResult:$mr Name:".$monitors->{$ip}->{'HASH'}->{Name}." MMap address:".$monitors->{$ip}->{'HASH'}->{MMapAddr}."\n";
   #my $lc = 0;
   zmMemInvalidate($monitors->{$ip}->{'HASH'});
   my $mv = zmMemVerify($monitors->{$ip}->{'HASH'});
   $monitors->{$ip}->{LastState} = zmGetMonitorState( $monitors->{$ip}->{'HASH'} );
   $monitors->{$ip}->{LastEvent} = zmGetLastEvent( $monitors->{$ip}->{'HASH'} );
        # while ( ! $mr ) {
  	#         unless (exists $monitors->{$ip}->{'HASH'}) { warn "$ip - $time - Error: Something went wrong in validatemem loop, \$monitors->\{$ip\}->\{\'HASH\'\} is not defined"; return }
   	#	 unless (exists $monitors->{$ip}->{'HASH'}->{Id}) { warn "$ip - $time - Error: Something went wrong in validatemem loop, \$monitors->\{$ip\}->\{\'HASH\'\}->\{\'Id\'\} is not defined"; return }
        #         zmMemInvalidate($monitors->{$ip}->{'HASH'});
        #         my $mv = zmMemVerify($monitors->{$ip}->{'HASH'});
	#	 $monitors->{$ip}->{LastState} = zmGetMonitorState( $monitors->{$ip}->{'HASH'} );
	#	 $monitors->{$ip}->{LastEvent} = zmGetLastEvent( $monitors->{$ip}->{'HASH'} );
	#	if (!defined($mv)) { 
	#	    warn ("$ip - $time - Cant verify memory for monitor ".$monitors->{$ip}->{'HASH'}->{Id}.", zoneminder may be stopped\n");
	#	    $mr = 0; sleep 15;
	#	} else {
        #            warn ("$ip - $time - Reloading memory for monitor ".$monitors->{$ip}->{'HASH'}->{Id}.", status of verify is:$mv\n");
        #            #$mr = zmMemRead($monitors->{$ip}->{'HASH'}, "shared_data:valid");
	#	    $mr = zmMemVerify($monitors->{$ip}->{'HASH'});
	#	}
	#	if ($lc eq 6) { $mr = 1 } #Max loops
	#	$lc++; 
        # }
}


sub isAlarmInactive {
	my ($ip,$storedAlarmTime) = @_;
	my $time; 
	my $timee; 
	my $alarmtime;
	my $ua = LWP::UserAgent->new();
	$ua->timeout(5);
	my $Manufacturer = $monitors->{$ip}->{'HASH'}->{Manufacturer};
	my $TimerType = $CamTypeMap->{$Manufacturer}->{'timer'};
	
	
	if ($TimerType eq 'local') {
		$alarmtime = $storedAlarmTime + $alarmdelay;
		$timee = time();
		if ($alarmtime <= $timee) { return 1 }
		return 0;
		
	} elsif ($Manufacturer eq 'HikVision') {	
 
		## Make sure we have a valid date and strip the timezone or return 0
		if ($storedAlarmTime =~ m/(....-..-..T..:..:..).*/) { $alarmtime = Time::Piece->strptime("$1", '%Y-%m-%dT%H:%M:%S')->epoch } else { return 0 } 
		$alarmtime = $alarmtime + $alarmdelay; # alarm delay time, the alarm is cleared after this. Add the time to the last active alert

		#my $time = `$curl -s -S -N -u $monitors->{$ip}->{'CREDS'} http://$ip/ISAPI/System/time/localTime`; # Get the current time from the cam
 
		my $req = $ua->get('http://'.$monitors->{$ip}->{'CREDS'}.'@'.$ip.$TimerType);
		if ($req->is_success) {
			$time = $req->content;
		} else {
			return 1; #disable the alarm because we failed to connect to the cam.
		}

		## strip the timezone info off (-6:00 ) and verify a valid date/time
		if ($time =~ m/(....-..-..T..:..:..).*/) { $timee = Time::Piece->strptime("$1", '%Y-%m-%dT%H:%M:%S')->epoch } else { return 0 } 

		#print "Current Time: ". Time::Piece->strptime("$timee", '%s') ." -- Alarm time: ". Time::Piece->strptime("$alarmtime", '%s') ."\n"; 
 
		if ($alarmtime <= $timee) { return 1 }
		
		return 0;
	}
}


sub loadMonitors {
	my @ipcred; 
	my $sql; 
	my $sth; 
	my $res; 
	my $cred;


	my $dbh = zmDbConnect();
	#$sql = "select Host,Id,Name,Function,Type,Path from Monitors where find_in_set( Function, 'Modect,Record,Nodect,Mocord' )";
	#$sql = "select Host,Id,Name,Type,Path,Capturing,Recording,Analysing from Monitors where Capturing = \'Always\' and Recording != \'None\' and Analysing = \'None\'";
	$sql = "select Monitors.Host,Monitors.Id,Monitors.Name,Monitors.Type,Monitors.Path,Monitors.Capturing,Monitors.Recording,Monitors.Analysing,Monitors.User,Monitors.Pass,Manufacturers.Name AS Manufacturer from Monitors LEFT OUTER JOIN Manufacturers ON Monitors.ManufacturerId=Manufacturers.Id where Capturing = \'Always\' and Recording != \'None\' and Analysing = \'None\'";
	#$sql = "select * from Monitors where find_in_set( Function, 'Modect,Record,Nodect,Mocord' )".( $Config{ZM_SERVER_ID} ? 'AND ServerId=?' : '' );
	$sth = $dbh->prepare_cached( $sql ) or Fatal( "Can't prepare '$sql': ".$dbh->errstr() );
	$res = $sth->execute() or Fatal( "Can't execute: ".$sth->errstr() );
	while( my $row = $sth->fetchrow_hashref() ) {
		if (!($row->{Name} =~ m/$matchstr/)) { next }
		#if ($row->{Type} eq 'Ffmpeg') { 
		#   $cred = $row->{Path};
		#   $cred =~ s/rtsp:\/\///;
		#   $cred =~ s/\/.*//;
		#   if ($cred =~ /(.*@.*):.*$/) { $cred = $1; } 
		# } else {
		#	$cred = $row->{Host};
		# }
		
		my $Host = $row->{'Host'};
		my $Path = $row->{'Path'};
		my $User = $row->{'User'};
		my $Pass = $row->{'Pass'};

		my $ip;
		my $userpass;
		
		if (defined $User && defined $Pass) {
			$userpass = $User.':'.$Pass;
		}
		
		#From Path Field for ffmpeg
		if ($row->{Type} eq 'Ffmpeg') { 
			#://user:pass@ipaddress:portnum/
			if ($Path =~ m/:\/\/(.*?):(.*?)@(.*?):\d+?\//) {
				$ip = $3;
				$userpass = $1.':'.$2 unless (defined $userpass);
				
			#://user:pass@ipaddress/
			} elsif ($Path =~ m/:\/\/(.*?):(.*?)@(.*?)\//) {
				$ip = $3;
				$userpass = $1.':'.$2 unless (defined $userpass);
				
			#://ipaddress:portnum/
			} elsif ($Path =~ m/:\/\/(.*?):\d+?\//) {	
				$ip = $1;
				
			#://ipaddress/
			} elsif ($Path =~ m/:\/\/(.*?)\//) {
				$ip = $1;
			}
		
		#From Host Field
		} else {
			#user:pass@ipaddress
			if ($Host =~ m/^(.*?):(.*?)@(.*?)/) {
				$ip = $3;
				$userpass = $1.':'.$2 unless (defined $userpass);
				
			#ipaddress
			} elsif ($Host =~ m/(.*)/) {
				$ip = $1;
			}
		}
			
			
		if ($row->{Recording} eq 'Always') {
			$monitors->{$ip}->{'FUNCT'} = 'Record';
				} elsif ($row->{Recording} eq 'OnMotion') {
			$monitors->{$ip}->{'FUNCT'} = 'Nodect';
				} else {
			next;
		}
		#print Dumper $monitors;
	
	
		$monitors->{$ip}->{'ID'} = $row->{Id};
		$monitors->{$ip}->{'CREDS'} = $userpass;
		$monitors->{$ip}->{'HASH'} = $row;
		if ( zmMemVerify( $row ) ) { # This will re-init shared memory
			$monitors->{$ip}->{LastState} = zmGetMonitorState( $row );
			$monitors->{$ip}->{LastEvent} = zmGetLastEvent( $row );
			$monitors->{$ip}->{lastReload} = time();
		}
	
	}
	
	$sql = "select Value from Config where Name = 'ZM_MAX_SUSPEND_TIME'";
	$sth = $dbh->prepare_cached( $sql ) or Fatal( "Can't prepare '$sql': ".$dbh->errstr() );
	$res = $sth->execute() or Fatal( "Can't execute: ".$sth->errstr() );
	
	while( my $row = $sth->fetchrow_hashref() ) {
		$params->{'SUS_TM'} = $row->{Value};
	}
}


############## Not used ################################

sub convertTimeStrToSeconds {
	my ($time) = @_;
	my $seconds;
	$time =~ s/\+//g;

	if($time!~/[0-9:,]+/) {
		$seconds=-1
	} else { 
		($seconds=$time)=~s{^(?:(\d+):)?(\d+)?(?:,(\d+))?$}{$1*3600+$2*60}e;
	}
	return $seconds;
}

