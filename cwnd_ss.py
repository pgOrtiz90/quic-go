#!/usr/bin/python

import csv
import socket
import signal
import select
import sys
import os
import inspect
import tempfile
import time
import subprocess
import random
from threading import Thread


#ss
def query_ss(epoch, port):
    #cmd = ["/bin/ss", "-into", "state", "established"]
    cmd = ["/bin/ss", "-into", "state", "established", '( sport = :%d )' % port]
    #output_field = ['ts', 'sack', 'coupled', 'wscale', 'rto', 'rtt', 'mss', 'cwnd', 'ssthresh', 'send', 'RATE', 'retrans', 'unacked', 'rcv_space']
    output_field = [ 'cwnd']
	
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    p.wait()
    line = p.stdout.readlines()

    #parse line to cvs: IP + CWND
    results = []
    idx = 1
    while idx < len(line) and len(line) > 2:
        ss_values = [epoch, '', str(time.time()), '']

        #IP
        x = line[idx].strip().split(' ')
        x = [i for i in x if i != '']
        ip = x[3]
        #ss_values.append(ip)
        #ss_values.append('\t')

        #TCP stuff
        cwnd = line[(idx+1)].strip().split()
        values = {}
        for x in cwnd:
            if not 'Kbps' in x and not 'Mbps' in x:
                if ':' in x:
                    parts = x.split(":")
                    values[parts[0]] = parts[1]
                else:
                    values[x] = x
            elif 'Kbps' in x:
                #normalize: Mbps
                x=x.split("Kbps")
                x = float(x[0])/1000.0
                values['RATE'] = str(x)
            elif 'Mbps' in x:
                x=x.split("Mbps")
                values['RATE'] = x[0]

        # append fields in our order to ss_values
        for f in output_field:
            #ss_values.append(f)
			
            if values.has_key(f):
               ss_values.append(values[f])
            else:
               ss_values.append('') #default value
        # append to results array
        results.append(ss_values)

        idx+=2
    return results


def monitor_sockets(stop_flag, first_port, flows, filename, epoch):
    print 'MONITORING SS - START'
    csvfile   = None
    csvwriter = None
    errors_occured = False
    try:
        # open file
        csv_filename = filename
        csvfile      = open(csv_filename, "wt")
        csvwriter    = csv.writer(csvfile, delimiter='\t')

        while stop_flag['ok']:
            for i in range(flows):
                try:
                    results = query_ss(epoch, first_port + i)
                    for ss_values in results:
                        csvwriter.writerow(ss_values)
                except:
                    errors_occured = True # just keep going, and report later

            # wait a bit before polling again to avoid 100% cpu
            time.sleep(0.02)
    except:
        errors_occured = True
        #traceback.print_exc()
    finally:
        try:
            csvfile.close()
        except:
            pass

        # signal that we are done
        print 'MONITORING SS - DONE', 'WITH ERRORS' if errors_occured else ''
        stop_flag['ended'] = True


def start_ss_monitoring(first_port, flows, filename, epoch):
    stop_flag = { 'ok': True, 'ended': False }
    thread = Thread(name = 'ss_monitor', target = monitor_sockets, args=(stop_flag, first_port, flows, filename, epoch, ))
    thread.start()
    return stop_flag


def end_ss_monitoring(stop_flag):
    stop_flag['ok'] = False
    while not stop_flag['ended']:
        time.sleep(0.1)


print("Starting Capture")
start_ss_monitoring(4242, 1, "cwnd_tcp.tr", 0)





