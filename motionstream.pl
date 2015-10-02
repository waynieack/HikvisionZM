#!/usr/bin/perl

#############################################################################
# Name: motionstream.pl ZoneMinder motion detection offload to camera
#
# Description: This script is for intergrating the motion detection on Hikvision
# cameras with Zoneminder reducing CPU usage on the zonminder server allowing for 
# a highly scailable solution
#
# Depends use Time::Piece, threads, ZoneMinder, DBI, LWP::UserAgent
#
# Author: Wayne Gatlin (wayne@razorcla.ws)
# $Revision: $
# $Date: $
#
##############################################################################
# Copyright       Wayne Gatlin, 2015, All rights reserved
##############################################################################
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
###############################################################################

#use strict;
use warnings;
use Time::Piece;
use threads;
use ZoneMinder;
use DBI;
use LWP::UserAgent;



my $alarmdelay = 10; #amount of time in seconds we wait before marking the motion event inactive
my $matchstr = '_mol-'; #Find any monitor with "_mol-" in the name
my $httptimeout = 30; #Amount of time we wait before saying the http stream is timed out in seconds
my $httpretry = 30; #Amount of time we wait before trying to reconnect to a timeout http stream in seconds
my %alarmtypeval; #Get other alarm types
$alarmtypeval{'VMD'} = '100';
$alarmtypeval{'linedetection'} = '150';

my %alarm;
my %monitors;
my %rcvbuf;
my %params;


&loadMonitors;
&startthreads;

sub startthreads
{
 my @threads;
    foreach my $ip ( keys %{$monitors} ) { 
       push @threads, async { (\&startstream($monitors->{$ip}->{'CREDS'},$ip)) };
    }
    foreach (@threads) {
       $_->join();
    }
}



sub startstream {
 my $thr = threads->self(); my $tid = $thr->tid;
 my ($creds, $ip) = @_;
 print "Starting thread $tid for IP $ip\n";
 my $ua = LWP::UserAgent->new();
 $ua->timeout($httptimeout);
 my $req = $ua->get('http://'.$creds.'@'.$ip.'/ISAPI/Event/notification/alertStream',
                                        ':content_cb' => \&ReadStream,
                                        ':read_size_hint' => 540,);


  if ($req->code) {
        print "$ip timed out!!!! Retrying\n";
	$rcvbuf->{$tid} = '';
	sleep $httpretry;
	&startstream($monitors->{$ip}->{'CREDS'},$ip);
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
	  if ( $Chunk =~ m/<eventType>VMD</) {
              &inserthash($Chunk);
	     #print "-----------------------\n";
             #print $alarm->{$tid}->{$ip}->{'VMD'}->{"dateTime"}."-- VMD -- Active\n";
             #print "-----------------------\n";

           }
	   elsif ( $Chunk =~ m/<eventType>linedetection</) {
              &inserthash($Chunk);
            #print "-----------------------\n";
            #print $alarm->{$tid}->{$ip}->{'linedetection'}->{"dateTime"}."-- linedetection -- Active\n";
            #print "-----------------------\n";

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
  my $rcvbuf = shift(@_); my $ip; my $eventType;
  my $thr = threads->self(); my $tid = $thr->tid; 
  if ($rcvbuf =~ m/<ipAddress>(.*)</) {
    $ip = $1;
     if ($rcvbuf =~ m/<eventType>(.*)</) { 
           $eventType = $1; 
           unless (exists $alarm->{$tid}->{$ip}) { $alarm->{$tid} = $ip }
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
 my $thr = threads->self(); my $tid = $thr->tid;
 my $function = $monitors->{$ip}->{'FUNCT'};
   if ( !zmIsAlarmed( $monitors->{$ip}->{'HASH'} ) and ($function eq 'Record' or $function eq 'Nodect') ) {
	  # zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
           zmTriggerEventOn( $monitors->{$ip}->{'HASH'}, $alarmtypeval{$type}, $type, $type );
           print "$ip -- monitor triggered by $type \n";
           $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
           return 1;
         }
     my ( $AlarmScore, $AlarmCause ) = zmMemRead( $monitors->{$ip}->{'HASH'}, [ "trigger_data:trigger_score", "trigger_data:trigger_cause" ] );
        if (($alarmtypeval{$type} > $AlarmScore) and ($function eq 'Record' or $function eq 'Nodect')) {
	   # zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
            zmTriggerEventOn( $monitors->{$ip}->{'HASH'}, $alarmtypeval{$type}, $type, $type );
            $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
            print "$ip -- monitor updated by $type \n";
            return 1;
          }
     if ($function eq 'Modect' or $function eq 'Mocord') {
         zmMonitorResume( $monitors->{$ip}->{'HASH'} );
         print "$ip -- monitor resumed by $type \n";
         $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
         return 1;
       }

    $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 1;
  }


 sub checkforinactive {
   my $ip = $_[0];  my $function = $monitors->{$ip}->{'FUNCT'};
   my $thr = threads->self(); my $tid = $thr->tid;
           foreach my $type ( keys %{$alarm->{$tid}->{$ip}} ) {
		my $skipchk = &skipcheck($ip ,$type);
		if ($skipchk eq 1) {
                   #print "CHecking $tid -> $ip -> $type -> dateTime for activity\n";                 
                   if (&isAlarmInactive($alarm->{$tid}->{$ip}->{$type}->{'dateTime'},$ip)) {
			 print "Disabling $tid -> $ip -> $type -> dateTime due to inactivity\n";
                         &disablezmalarm($ip, $type); #disable zoneminder alert
                    }
		 }
		elsif ($skipchk eq 2) {
		  &disablezmalarm($ip, $type);
		}   


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
  my $thr = threads->self(); my $tid = $thr->tid;
           foreach my $type ( keys %{$alarm->{$tid}->{$ip}} ) {
		if (exists $alarm->{$tid}->{$ip}->{$type}->{'isActive'}) {
                   if ( $alarm->{$tid}->{$ip}->{$type}->{'isActive'} ) {
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

 if ( $function eq 'Modect' or $function eq 'Mocord' ) { #need to figure out how to check if the monitor is suspended, get auto resume time
              if ($activecount > 1) {
                  print "$ip -- monitor suspended\n";
                  delete $alarm->{$tid}->{$ip}->{$type}; #just delete the active alarm from the hash because we have other active ones
                  return 1;
                }
              if ($activecount eq 1) {
                  $monitors->{$ip}->{'RESUS'} = ($params->{'SUS_TM'} + time) - 2;
                  zmMonitorSuspend( $monitors->{$ip}->{'HASH'} ); #suspend the ZM motion detection because our camera motion event cleared
                  print "$ip -- monitor suspended\n";
                  $alarm->{$tid}->{$ip}->{$type}->{"isActive"} = 0; #clear the active flag
                #  delete $alarm->{$tid}->{$ip}->{$type}->{'dateTime'}; #delete the date so we dont continue to check it
                  return 1;
                }
               if (time >= $monitors->{$ip}->{'RESUS'} ) {
                  $monitors->{$ip}->{'RESUS'} = ($params->{'SUS_TM'} + time) - 2; # set the resume time, adding the ZM configured time to the current time
                  zmMonitorSuspend( $monitors->{$ip}->{'HASH'} ); #resuspend the ZM motion detection due to the ZM auto resume feature 
		  print "$ip -- monitor REsuspended\n";
                  return 1;
                }
         }


 if ( ($function eq 'Record' or $function eq 'Nodect') and (zmIsAlarmed($monitors->{$ip}->{'HASH'}) and $activecount eq 1) ) {
              #zmTriggerEventOff( $monitors->{$ip}->{'HASH'} );
              zmTriggerEventCancel( $monitors->{$ip}->{'HASH'} );
              print "$ip -- monitor $type disabled\n";
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
              	print "$ip -- monitor $type disabled\n";
              	delete $alarm->{$tid}->{$ip}->{$type};
              	return 1;
		}
         }


        delete $alarm->{$tid}->{$ip}->{$type};
  }




sub isAlarmInactive {
 my $ip = $_[1]; my $time; my $timee; my $alarmtime;
 my $ua = LWP::UserAgent->new();
 $ua->timeout(5);
 
  ## Make sure we have a valid date and strip the timezone or return 0
 if ($_[0] =~ m/(....-..-..T..:..:..).*/) { $alarmtime = Time::Piece->strptime("$1", '%Y-%m-%dT%H:%M:%S')->epoch } else { return 0 } 
 $alarmtime = $alarmtime + $alarmdelay; # alarm delay time, the alarm is cleared after this. Add the time to the last active alert

 #my $time = `$curl -s -S -N -u $monitors->{$ip}->{'CREDS'} http://$ip/ISAPI/System/time/localTime`; # Get the current time from the cam
 
  my $req = $ua->get('http://'.$monitors->{$ip}->{'CREDS'}.'@'.$ip.'/ISAPI/System/time/localTime');
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
my @ipcred; my $sql; my $sth; my $res;
	my $dbh = zmDbConnect();
        $sql = "select Host,Id,Name,Function from Monitors where find_in_set( Function, 'Modect,Record,Nodect,Mocord' )";
        $sth = $dbh->prepare_cached( $sql ) or Fatal( "Can't prepare '$sql': ".$dbh->errstr() );
        $res = $sth->execute() or Fatal( "Can't execute: ".$sth->errstr() );
        while( my $row = $sth->fetchrow_hashref() )
        {
		  if (!($row->{Name} =~ m/$matchstr$/)) { next }
                  my @ipcred = split('@', $row->{Host});
                  $monitors->{$ipcred[1]}->{'ID'} = $row->{Id};
                  $monitors->{$ipcred[1]}->{'CREDS'} = $ipcred[0];
                  $monitors->{$ipcred[1]}->{'HASH'} = $row;
		  $monitors->{$ipcred[1]}->{'FUNCT'} = $row->{Function};

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

