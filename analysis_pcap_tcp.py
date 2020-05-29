import dpkt
import time
import sys


# Get only TCP connections
def connections(pcap, tcpconnect, wind, timeval):
    for ts, buf in pcap:
        ethnt = dpkt.ethernet.Ethernet(buf)
        if ethnt.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = ethnt.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        tcpconnect.append(tcp)
        timeval.append(ts)
        if tcp.flags & dpkt.tcp.TH_SYN:
            wind.append(buf[73])


# Get number of flows
def getflows(tcpconnect, src, dest):
    flowcounter = 0
    for tcp in tcpconnect:
        if tcp.flags & dpkt.tcp.TH_SYN:
            src.append(tcp.sport)
        if tcp.flags & dpkt.tcp.TH_FIN:
            flowcounter += 1
            dest.append(tcp.dport)
    return flowcounter // 2


def flow_order(tcpconnect, src, destorder, order, i, flowindex, timeval, timestamp):
    for num, tcp in enumerate(tcpconnect):
        if tcp.sport == src[i]:
            order.append(tcp)
            timestamp.append(timeval[num])
        if tcp.dport == src[i]:
            destorder.append(tcp)
            timestamp.append(timeval[num])
        else:
            continue
    for n in destorder:
        order.append(n)
    flowindex.append(len(order))


def complete_order(tcpconnect, src, completeorder, i):
    for num, tcp in enumerate(tcpconnect):
        if tcp.sport == src[i]:
            completeorder.append(tcp)
        if tcp.dport == src[i]:
            completeorder.append(tcp)
        else:
            continue


def two_transact(completeorder, windsize, flowindex,n, src):
    scount = 1
    dcount = 1
    ind = flowindex[n]
    for i in range(ind + 3, len(completeorder)):
        if scount == 3:
            break
        if completeorder[i].sport == src[n]:
            print('Sender Seq num ' + str(scount) + ': ', end=' ')
            print(completeorder[i].seq)
            print('Sender Ack num ' + str(scount) + ': ', end=' ')
            print(completeorder[i].ack)
            print('Sender Rwnd ' + str(scount) + ': ', end=' ')
            x = 2 ** windsize
            size = x * completeorder[i].win
            print(size)
            print('-------------------------------------------------')
            scount += 1
    for i in range(ind + 3, len(completeorder)):
        if dcount == 3:
            break
        if completeorder[i].dport == src[n]:
            print('Receive Seq num ' + str(dcount) + ': ', end=' ')
            print(completeorder[i].seq)
            print('Receive Ack num ' + str(dcount) + ': ', end=' ')
            print(completeorder[i].ack)
            print('Recieve Rwnd ' + str(dcount) + ': ', end=' ')
            x = 2 ** windsize
            size = x * completeorder[i].win
            print(size)
            print('-------------------------------------------------')
            dcount += 1


def flowlength(flowindex, order, start):
    flen = 0
    for i in range(start, flowindex[start + 1]):
        flen += len(order[i].data)
    return flen


def throughpt(flowindex, timestamp, start):
    first = flowindex[start]
    end = flowindex[start + 1]
    difference = timestamp[end - 1] - timestamp[first]
    return difference


def congesttime(flowindex, timestamp, i):
    begin = flowindex[i]
    time = timestamp[begin + 1] - timestamp[begin]
    return time


def packetamount(tcpconnect, rtt, n, y, src, counter):
    oldtime = time.time()
    newtime = oldtime
    difference = 0
    for i in range(y, len(tcpconnect)):
        if tcpconnect[n].sport == src[n]:
            counter += 1
            newtime = time.time()
            difference = newtime - oldtime
        if difference < rtt:
            break
    return (counter, i)


def triplestart(order, start, src, val, startlist):
    for i in range(start, len(order)):
        if order[i].dport == src[val]:
            startlist.append(i)
            break


def tripleack(startind, stopind, completeorder, src, i):
    counter = 0
    pack = 0
    val = 0
    for num in range(startind + 3, len(completeorder)):
        if (completeorder[num].dport == src[i]) and (val != completeorder[num].ack):
            val = completeorder[num].ack
            continue
        if (completeorder[num].dport == src[i]) and completeorder[num].ack == val:
            counter += 1
        if counter == 3:
            counter = 0
            pack += 1
            val = completeorder[num].ack
        if num == stopind:
            break
    return pack


def timeout(stopind, startind, completeorder, src, i):
    counter = 0
    seqval = completeorder[startind].seq
    for num in range(startind, len(completeorder)):
        if (completeorder[num].sport == src[i]) and completeorder[num].seq == seqval:
            counter += 1
            continue
        if completeorder[num].sport == src[i] and completeorder[num].seq != seqval:
            seqval = completeorder[num].seq
            continue
        if num == stopind:
            break

    return counter


def main():
    print("Please input pcap file")
    x = input()
    file = open(x, 'rb')
    pcap = dpkt.pcap.Reader(file)
    tcpconnect = []
    src = []
    dest = []
    order = []
    destorder = []
    flowindex = [0]
    wind = []
    timeval = []
    timestamp = []
    startlist = []
    completeorder = []
    connections(pcap, tcpconnect, wind, timeval)
    num = getflows(tcpconnect, src, dest)
    dest = dest[0]
    src = list(dict.fromkeys(src))
    src.remove(dest)
    print('TCP connection flows initiated from the sender: ', end=' ')
    print(num)
    print('***********************************************************')
    for i in range(len(src)):
        flow_order(tcpconnect, src, destorder, order, i, flowindex, timeval, timestamp)
        complete_order(tcpconnect, src, completeorder, i)
        destorder.clear()
    end = flowindex.pop()
    windsize = wind[0]
    for i in range(len(src)):
        print('***********************************************************')
        print('Flow ' + str(i + 1))
        two_transact(completeorder, windsize, flowindex, i, src)
    flowindex.append(end)
    for i in range(len(src)):
        print('***********************************************************')
        print('Flow ' + str(i + 1))
        print('Sender Throughput: ', end=' ')
        val = flowlength(flowindex, order, i)
        throughdiff = throughpt(flowindex, timestamp, i)
        print(str(val / throughdiff) + ' bytes/s')
    for i in range(len(src)):
        rtt = congesttime(flowindex, timestamp, i)
        print('***********************************************************')
        print('Flow ' + str(i + 1))
        print('CWND1: ', end=' ')
        x = packetamount(tcpconnect, rtt, i, 0, src, 1)
        print(str(x[0]) + ' packets')
        print('CWND2: ', end=' ')
        y = packetamount(tcpconnect, rtt, i, x[1] + 1, src, x[0] * 2)
        print(str(y[0]) + ' packets')
        print('CWND3: ', end=' ')
        a = packetamount(tcpconnect, rtt, i, y[1] + 1, src, y[0] * 2)
        print(str(a[0]) + ' packets')
        print('CWND4: ', end=' ')
        b = packetamount(tcpconnect, rtt, i, a[1] + 1, src, a[0] * 2)
        print(str(b[0]) + ' packets')
        print('CWND5: ', end=' ')
        c = packetamount(tcpconnect, rtt, i, b[1] + 1, src, b[0] * 2)
        print(str(c[0]) + ' packets')
    for i in range(len(src)):
        triplestart(order, flowindex[i], src, i, startlist)

    for i in range(len(src)):
        print('***********************************************************')
        print('Flow ' + str(i + 1))
        print("Triple dup Ack: ", end=' ')
        ok = tripleack(flowindex[i], flowindex[i+1], order, src, i)
        print(ok)
        print('Timeout: ', end=' ')
        bob = timeout(flowindex[i + 1], flowindex[i], completeorder, src, i)
        print(bob)


if __name__ == "__main__":
    main()
