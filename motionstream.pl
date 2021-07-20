#!/usr/bin/perl
#use strict;
use warnings;
use Time::Piece;
use threads;
use ZoneMinder;
use DBI;
use LWP::UserAgent;
use Fcntl ':flock';

# Version 1.2.4
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

my %alarmtypeval; # Set zoneminder score for detection types
$alarmtypeval{'VMD'} = '100';            # Motion Detection
$alarmtypeval{'shelteralarm'} = '120';   # Video Tampering
$alarmtypeval{'fielddetection'} = '140'; # Intrusion Detection
$alarmtypeval{'linedetection'} = '150';  # Line Crossing Detection
$alarmtypeval{'PIR'} = '200';            # IR Motion Detection

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

sub startthreads
{
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
 my $thr = threads->self(); my $tid = $thr->tid;
 my ($creds, $ip) = @_;

	# $|=1; # autoflush
	#  my $FH = $monitors->{$ip}->{'FH'};
	#  open(FH, '>>', $LogPath."motionstream-$ip.log")
	#	or warn "Cannot open $files: $OS_ERROR";
	#  print FH "Starting thread $tid for IP $ip\n"
	#	or warn "Cannot write to $files: $OS_ERROR";

 	warn scalar(localtime)." - Starting thread $tid for IP $ip\n";
	$alarm->{$tid} = $ip;
	&cameraconnect($creds,$ip,$tid);
}


sub cameraconnect { 
	my ($creds, $ip, $tid) = @_;
	my $ua = LWP::UserAgent->new();
 	$ua->timeout($httptimeout);
 	my $req = $ua->get('http://'.$creds.'@'.$ip.$ISAPI.'/Event/notification/alertStream',
                                        		':content_cb' => \&ReadStream,
                                        		':read_size_hint' => 540,);


  	if ($req->code) {
        	warn "$ip - ".scalar(localtime)." - timed out! - HTTPCode: ". $req->code ." -- Retrying\n";
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

 #print $msg;

while (1) {
  if ($msg  =~ m/(<ipAddress>)(.*?)--boundary(.*)/s) {
     $Chunk = "$1$2"; #print $Chunk;
	 $msg = $3; #grab whats left after the full message
		    #to see if its a full message on the next loop
		    #or save it to the buffer
	   foreach my $eventype ( keys %alarmtypeval ) {
	    $eventype = '<eventType>'.$eventype.'<'; 
	    if ( $Chunk =~ m/$eventype/) {
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
&checkforinactive($ip) if (defined $ip);
}


sub inserthash {
  my ($rcvbuf, $ip) = @_; my $eventType;
  my $thr = threads->self(); my $tid = $thr->tid; 
  if ($rcvbuf =~ m/<ipAddress>(.*)</) {
    #$ip = $1;
     if ($rcvbuf =~ m/<eventType>(.*)</) { 
           $eventType = $1; 
           #unless (exists $alarm->{$tid}->{$ip}) { $alarm->{$tid} = $ip }
           #if ($rcvbuf =~ m/<activePostCount>(.*)</) {
           #  $alarm->{$tid}->{$ip}->{$eventType}->{"activePostCount"} = $1;
           # }

            if ($rcvbuf =~ m/<dateTime>(.*)</) {
	      unless (exists $alarm->{$tid}->{$ip}->{$eventType}->{'isActive'}) { &activatezmalarm($ip, $eventType) }
	      elsif (!$alarm->{$tid}->{$ip}->{$eventType}->{'isActive'}) { &activatezmalarm($ip, $eventType) }
              $alarm->{$tid}->{$ip}->{$eventType}->{'dateTime'} = $1;
             }
	return 1;
       }
     }
}

sub activatezmalarm {
 my $ip = $_[0]; my $type = $_[1];
 my $time = scalar(localtime);
 my $thr = threads->self(); my $tid = $thr->tid;
 my $function = $monitors->{$ip}->{'FUNCT'};
 &validatemem($ip);
   if ( !zmIsAlarmed( $monitors->{$ip}->{'HASH'} ) and ($function eq 'Record' or $function eq 'Nodect') ) {
	   zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
           zmTriggerEventOn( $monitors->{$ip}->{'HASH'}, $alarmtypeval{$type}, $type, $type );
           warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." triggered by $type\n";
           $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
           return 1;
         }
     my ( $AlarmScore, $AlarmCause ) = zmMemRead( $monitors->{$ip}->{'HASH'}, [ "trigger_data:trigger_score", "trigger_data:trigger_cause" ] );
        if (($alarmtypeval{$type} > $AlarmScore) and ($function eq 'Record' or $function eq 'Nodect')) {
	    zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
            zmTriggerEventOn( $monitors->{$ip}->{'HASH'}, $alarmtypeval{$type}, $type, $type );
            $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
            warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." updated by $type \n";
            return 1;
          }
     if ($function eq 'Modect' or $function eq 'Mocord') {
         zmMonitorResume( $monitors->{$ip}->{'HASH'} );
         warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." resumed by $type \n";
         $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
         return 1;
       }

    $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
  }


 sub checkforinactive {
   my $ip = $_[0];  my $function = $monitors->{$ip}->{'FUNCT'};
   my $time = scalar(localtime);
   my $thr = threads->self(); my $tid = $thr->tid;
           foreach my $type ( keys %{$alarm->{$tid}->{$ip}} ) {
		my $skipchk = &skipcheck($ip ,$type);
		if ($skipchk eq 1) {
			#warn "CHecking $tid -> $ip -> $type -> dateTime for activity\n";                 
                   if (&isAlarmInactive($alarm->{$tid}->{$ip}->{$type}->{'dateTime'},$ip)) {
			 warn "$ip - $time - Disabling $tid -> $ip -> $type -> dateTime due to inactivity\n";
                         &disablezmalarm($ip, $type); #disable zoneminder alert
                    }
		 }
		elsif ($skipchk eq 2) {
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
 my $ip = $_[0]; my $type = $_[1];
 my $function = $monitors->{$ip}->{'FUNCT'};
 my $thr = threads->self(); my $tid = $thr->tid;

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
     if ($alarm->{$tid}->{$ip}->{$type}->{'dateTime'}->{chktime} eq time) { return 0 } else { return 1 }
   }  
         
  
 sub checkforactivecount {
  my $ip = $_[0];  my @ret;
  my $time = scalar(localtime);
  my $thr = threads->self(); my $tid = $thr->tid;
           foreach my $type ( keys %{$alarm->{$tid}->{$ip}} ) {
		if (exists $alarm->{$tid}->{$ip}->{$type}->{'isActive'}) {
                   if ( $alarm->{$tid}->{$ip}->{$type}->{'isActive'} ) {
			warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." Currently Active Alarm Type - $type\n";
			push (@ret, $type);
                     }
		 }
              }
	  return @ret;
    }




sub disablezmalarm {
 my $ip = $_[0]; my $type = $_[1]; my $pname = "";
 my $thr = threads->self(); my $tid = $thr->tid;
 my @activetype = &checkforactivecount($ip);
 my $function = $monitors->{$ip}->{'FUNCT'};
 my $activecount = scalar @activetype;
 my $time = scalar(localtime);
 warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." Currently Active Alarm Count - $activecount\n";
 &validatemem($ip);

 if ( $function eq 'Modect' or $function eq 'Mocord' ) { #need to figure out how to check if the monitor is suspended, get auto resume time
              if ($activecount > 1) {
                  warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." suspended\n";
                  delete $alarm->{$tid}->{$ip}->{$type}; #just delete the active alarm from the hash because we have other active ones
                  return 1;
                }
              if ($activecount eq 1) {
                  $monitors->{$ip}->{'RESUS'} = ($params->{'SUS_TM'} + time) - 2;
                  zmMonitorSuspend( $monitors->{$ip}->{'HASH'} ); #suspend the ZM motion detection because our camera motion event cleared
                  warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." suspended\n";
                  $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 0; #clear the active flag
                #  delete $alarm->{$tid}->{$ip}->{$type}->{'dateTime'}; #delete the date so we dont continue to check it
                  return 1;
                }
               if (time >= $monitors->{$ip}->{'RESUS'} ) {
                  $monitors->{$ip}->{'RESUS'} = ($params->{'SUS_TM'} + time) - 2; # set the resume time, adding the ZM configured time to the current time
                  zmMonitorSuspend( $monitors->{$ip}->{'HASH'} ); #resuspend the ZM motion detection due to the ZM auto resume feature 
		  warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." REsuspended\n";
                  return 1;
                }
         }


 if ( ($function eq 'Record' or $function eq 'Nodect') and (zmIsAlarmed($monitors->{$ip}->{'HASH'}) and $activecount eq 1) ) {
              #zmTriggerEventOff( $monitors->{$ip}->{'HASH'} );
              zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
              warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." type - $type disabled\n";
              delete $alarm->{$tid}->{$ip}->{$type};
	      return 1;
         }


 if ( ($function eq 'Record' or $function eq 'Nodect') and (zmIsAlarmed($monitors->{$ip}->{'HASH'}) and $activecount > 1) ) {
		foreach my $name (@activetype) {
		 if ($name eq $type) { next } 
		 if ($pname eq "") {$pname = $name; next;}
		 if ($alarmtypeval{$name} > $alarmtypeval{$pname}) { $pname = $name }
		}

	      if (!$pname eq "" ) { 
		zmTriggerEventOn($monitors->{$ip}->{'HASH'}, $alarmtypeval{$pname}, $pname, $pname );  
              	warn "$ip - $time - Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." type - $type key deleted (ZM alarm is still active due to another alarm)\n";
              	delete $alarm->{$tid}->{$ip}->{$type};
              	return 1;
		}
         }


        delete $alarm->{$tid}->{$ip}->{$type};
  }


sub validatemem {
   my $ip = $_[0];
   my $time = scalar(localtime);
   unless (defined ($ip)) { warn "$time - Error: Something went wrong in validatemem, IP is not defined."; return }
   unless (exists $monitors->{$ip}->{'HASH'}) { warn "$ip - $time - Error: Something went wrong in validatemem, \$monitors->\{$ip\}->\{\'HASH\'\} is not defined"; return }
   unless (exists $monitors->{$ip}->{'HASH'}->{Id}) { warn "$ip - $time - Error: Something went wrong in validatemem, \$monitors->\{$ip\}->\{\'HASH\'\}->\{\'Id\'\} is not defined"; return }
   $monitors->{$ip}->{lastReload} = time();
   #my $mr = zmMemRead($monitors->{$ip}->{'HASH'}, "shared_data:valid");
   
   my $mr = zmMemVerify($monitors->{$ip}->{'HASH'});
   $mr = 0 unless (defined($mr)); 
   warn "$ip - $time - Checking Monitor ".$monitors->{$ip}->{'HASH'}->{Id}." MemReadResult:$mr Name:".$monitors->{$ip}->{'HASH'}->{Name}." MMap address:".$monitors->{$ip}->{'HASH'}->{MMapAddr}."\n";
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
 my $ip = $_[1]; my $time; my $timee; my $alarmtime;
 my $ua = LWP::UserAgent->new();
 $ua->timeout(5);
 
  ## Make sure we have a valid date and strip the timezone or return 0
 if ($_[0] =~ m/(....-..-..T..:..:..).*/) { $alarmtime = Time::Piece->strptime("$1", '%Y-%m-%dT%H:%M:%S')->epoch } else { return 0 } 
 $alarmtime = $alarmtime + $alarmdelay; # alarm delay time, the alarm is cleared after this. Add the time to the last active alert

 #my $time = `$curl -s -S -N -u $monitors->{$ip}->{'CREDS'} http://$ip/ISAPI/System/time/localTime`; # Get the current time from the cam
 
  my $req = $ua->get('http://'.$monitors->{$ip}->{'CREDS'}.'@'.$ip.$ISAPI.'/System/time/localTime');
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


sub loadMonitors
{
#my $ip = $_[0] if (defined $_[0]);
my @ipcred; my $sql; my $sth; my $res; my $cred;

#if (defined $ip) { $sql = "select Host,Id,Name,Function from Monitors WHERE Host like '%$ip'" }
#else { $sql = "select Host,Id,Name,Function from Monitors where find_in_set( Function, 'Modect,Record,Nodect,Mocord' )" }

	my $dbh = zmDbConnect();
        $sql = "select Host,Id,Name,Function,Type,Path from Monitors where find_in_set( Function, 'Modect,Record,Nodect,Mocord' )";
        #$sql = "select * from Monitors where find_in_set( Function, 'Modect,Record,Nodect,Mocord' )".( $Config{ZM_SERVER_ID} ? 'AND ServerId=?' : '' );
	$sth = $dbh->prepare_cached( $sql ) or Fatal( "Can't prepare '$sql': ".$dbh->errstr() );
        $res = $sth->execute() or Fatal( "Can't execute: ".$sth->errstr() );
        while( my $row = $sth->fetchrow_hashref() )
        {
		  if (!($row->{Name} =~ m/$matchstr/)) { next }
		  if ($row->{Type} eq 'Ffmpeg') { 
		     $cred = $row->{Path};
		     $cred =~ s/rtsp:\/\///;
                     $cred =~ s/\/.*//;
		     if ($cred =~ /(.*@.*):.*$/) { $cred = $1; } 
		   } else {
		     $cred = $row->{Host};
		   }
                  @ipcred = split('@', $cred);
		  my $ip = $ipcred[1];
		  my $userpass = $ipcred[0];
                  $monitors->{$ip}->{'ID'} = $row->{Id};
                  $monitors->{$ip}->{'CREDS'} = $userpass;
                  $monitors->{$ip}->{'HASH'} = $row;
		  $monitors->{$ip}->{'FUNCT'} = $row->{Function};
    		  if ( zmMemVerify( $row ) ) { # This will re-init shared memory
        		$monitors->{$ip}->{LastState} = zmGetMonitorState( $row );
        		$monitors->{$ip}->{LastEvent} = zmGetLastEvent( $row );
			$monitors->{$ip}->{lastReload} = time();
			#print "Monitor: ".$monitors->{$ipcred[1]}->{'ID'}." LastState: ". $monitors->{$ipcred[1]}->{LastState} ." LastEvent: ". $monitors->{$ipcred[1]}->{LastEvent}."\n";
    		  }

        }
	$sql = "select Value from Config where Name = 'ZM_MAX_SUSPEND_TIME'";
        $sth = $dbh->prepare_cached( $sql ) or Fatal( "Can't prepare '$sql': ".$dbh->errstr() );
        $res = $sth->execute() or Fatal( "Can't execute: ".$sth->errstr() );
        while( my $row = $sth->fetchrow_hashref() )
        {
                  $params->{'SUS_TM'} = $row->{Value};
	}
}


############## Not used ################################
sub convertTimeStrToSeconds
{
my $time = $_[0]; my $seconds;
$time =~ s/\+//g;

 if($time!~/[0-9:,]+/) {$seconds=-1}
else { ($seconds=$time)=~s{^(?:(\d+):)?(\d+)?(?:,(\d+))?$}{$1*3600+$2*60}e;}
return $seconds;

}

