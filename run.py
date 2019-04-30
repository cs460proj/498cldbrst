import pyshark
import curses
import curses.ascii as cascii
from curses.textpad import rectangle
import time
import heapq
from collections import defaultdict, deque
from functools import partial
import ipaddress
import math
import datetime
import xxhash
import queue
import traceback
from threading import Thread

ascii_art = """\
 ██████╗██╗     ██████╗ ██████╗ ██████╗ ███████╗████████╗
██╔════╝██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
██║     ██║     ██║  ██║██████╔╝██████╔╝███████╗   ██║   
██║     ██║     ██║  ██║██╔══██╗██╔══██╗╚════██║   ██║   
╚██████╗███████╗██████╔╝██████╔╝██║  ██║███████║   ██║   
 ╚═════╝╚══════╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   
"""
ascii_art_len = len(ascii_art.split('\n')[0])+1

TERA = 1000000000000
GIGA = 1000000000
MEGA = 1000000
KILO = 1000
UPDATE_INTERVAL = 5 # seconds

PADDING = 2
SPACE_BETWEEN = 2 # lines each row takes up

PACKET_MAX = 3000

pkts = deque(PACKET_MAX*[0], PACKET_MAX)
nlargest = []
totals_src = {}
totals_srcport = {}
totals_dst = {}
totals_dstport = {}
pkt_queue = queue.Queue()
src_or_dst = False

last_update_time = datetime.datetime.fromtimestamp(0)
complete_total = 0
highlighted = 0
last_highlighted = 0
last_highlighted_val = None

def iterpop(iterable, fn, default=None):
    for idx, elem in enumerate(iterable):
        if fn(elem):
            del iterable[idx]
            return elem
    return default

def update_headers(windows, stats):
    windows.header.bkgd(curses.A_STANDOUT)
    windows.header.border(0,0,0,0)

    windows.header_data.bkgd(curses.A_STANDOUT)
    windows.header_data.border(0,0,0,0)

    windows.asciiart.bkgd(curses.A_STANDOUT)
    windows.asciiart.addstr(0, 0, ascii_art)

    windows.header_data.addstr(1, PADDING, f'Current Pkts: {min(stats.total_packets, PACKET_MAX)}      ')
    windows.header_data.addstr(2, PADDING, f'Queued Pkts:  {pkt_queue.qsize()}      ')
    windows.header_data.addstr(3, PADDING, f'Total Pkts:   {stats.total_packets}')
    windows.header_data.addstr(4, PADDING, f'Total Bytes:  {bytes_format(stats.total_transfer)}   ')
    windows.header_data.addstr(5, PADDING, f'Total Hosts:  {len(stats.hosts)}   ')

def bytes_format(_bytes: int):
    if _bytes > TERA:
        suffix = 'TB'
        val = _bytes // TERA
    elif _bytes > GIGA:
        suffix = 'GB'
        val = _bytes // GIGA
    elif _bytes > MEGA:
        suffix = 'MB'
        val = _bytes // MEGA
    elif _bytes > KILO:
        suffix = 'KB'
        val = _bytes // KILO
    else:
        suffix = ' B'
        val = _bytes

    return '{} {}'.format(val, suffix)

# 0 for src packets from nlargest
# 1 for dst packets from nlargest
def packet_maintain(windows, stats):
    global pkts
    global pkt_heap
    global pkt_queue
    global totals_src
    global totals_dst
    global complete_total
    global nlargest

    while True:
        packet_count_diff = 0
        pkt = pkt_queue.get(True)
        packet_count_diff += 1

        new_len = int(str(pkt.captured_length), 10)
        stats.total_transfer += new_len

        to_remove = pkts.pop()
        pkts.appendleft(pkt)
        
        if hasattr(pkt, 'ip'):
            stats.hosts.add(int(ipaddress.IPv4Address(pkt.ip.src)))
            stats.hosts.add(int(ipaddress.IPv4Address(pkt.ip.dst)))

            totals_src[pkt.ip.src] = totals_src.get(pkt.ip.src, 0) + new_len
            totals_dst[pkt.ip.dst] = totals_dst.get(pkt.ip.dst, 0) + new_len

        if to_remove != 0:
            new_len = int(str(to_remove.captured_length), 10)
            stats.total_transfer -= new_len

            if hasattr(to_remove, 'ip'):
                totals_src[to_remove.ip.src] = totals_src.get(to_remove.ip.src) - new_len
                totals_dst[to_remove.ip.dst] = totals_dst.get(to_remove.ip.dst) - new_len
                packet_count_diff -= 1

        stats.total_packets += packet_count_diff

        calculate_nlargest(windows)

def calculate_nlargest(windows):
    global nlargest

    nlargest_dict = totals_dst if src_or_dst else totals_src
    nlargest = heapq.nlargest(main_window_row_count(windows) // SPACE_BETWEEN, nlargest_dict.items(), lambda x: x[1])

def main_window_row_count(windows):
    (max_y, max_x) = windows.main.getmaxyx()
    return (max_y - PADDING*2)

def draw_byte_sort(windows, do_clear, do_update):
    global highlighted
    global last_highlighted
    global last_highlighted_val
    global last_update_time
    global nlargest

    correct_dict = totals_dst if src_or_dst else totals_src
    if len(correct_dict) == 0 or not hasattr(windows, 'main'):
        return last_highlighted_val

    max_num = main_window_row_count(windows) // SPACE_BETWEEN
    highlighted = max(min(len(correct_dict)-1, highlighted, max_num-1), 0)

    now = datetime.datetime.utcnow()
    do_update = do_update or ((datetime.datetime.utcnow() - last_update_time).total_seconds() > UPDATE_INTERVAL)
    if (not do_update and last_highlighted == highlighted and not do_clear):
        return last_highlighted_val

    last_highlighted = highlighted
    last_update_time = now
    (max_y, max_x) = windows.main.getmaxyx()

    format_str = '{:<20}  {:>6}{}'
    format_str_len = len(format_str.format('',bytes_format(100),' '*PADDING))

    max_bytes = nlargest[0][1]
    min_bytes = nlargest[min(max_num-1, len(nlargest)-1)][1]

    if max_bytes != min_bytes:
        scale_max = max_bytes - min_bytes
    else:
        scale_max = max_bytes

    log_base = 10

    scale_max = math.log(scale_max, log_base)

    if do_clear:
        windows.main.clear()
    windows.main.border(0,0,0,0)

    title_str = 'Sorting by: {}'.format('DST IP' if src_or_dst else 'SRC IP')
    title_start = (max_x // 2) - (len(title_str) // 2)
    windows.main.addstr(0, title_start, title_str, curses.A_STANDOUT)

    x_remaining = max_x - format_str_len - PADDING*2 - 2 # 2 at end for brackets on "loading" bar
    for idx, i in enumerate(nlargest):
        bytes_formatted = bytes_format(i[1])

        curr_y = PADDING + (idx*SPACE_BETWEEN)
        diff = max(1, i[1] - min_bytes)
        bar_pct = int((math.log(diff, log_base) / scale_max) * x_remaining)
        bar_pct = max(bar_pct, 1)

        args_ip = (curr_y, PADDING, format_str.format(i[0], bytes_formatted, ' '*PADDING))
        args_bar = (curr_y, PADDING+format_str_len, '[{}{}]'.format('='*bar_pct, ' '*(x_remaining-bar_pct)))
        if idx == highlighted:
            last_highlighted_val = i[0]
            windows.main.addstr(*args_ip, curses.A_STANDOUT)
            windows.main.addstr(*args_bar, curses.A_STANDOUT)
        else:
            windows.main.addstr(*args_ip)
            windows.main.addstr(*args_bar)

    return last_highlighted_val

def show_ip_details(windows, ip):
    to_ip = defaultdict(int) # map of ips that this ip sent data to (and how much)
    from_ip = defaultdict(int) # map of ips that this ip received data from (and how much)
    proto_counts = defaultdict(int)

    for x in pkts.copy():
        if hasattr(x, 'ip'):
            if x.ip.src == ip:
                to_ip[x.ip.dst] += int(str(x.captured_length), 10)
            if x.ip.dst == ip:
                from_ip[x.ip.src] += int(str(x.captured_length), 10)

        if hasattr(x, 'highest_layer'):
           proto_counts[x.highest_layer] += int(str(x.captured_length), 10)

    to_ip = sorted(to_ip.items(), key=lambda x: x[1], reverse=True)
    from_ip = sorted(from_ip.items(), key=lambda x: x[1], reverse=True)
    proto_sorted = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)

    rows = main_window_row_count(windows)
    (max_y, max_x) = windows.main.getmaxyx()
    title_start = (max_x // 2) - (len(ip) // 2)

    half_rows = PADDING + (rows // 2)

    from_ip_rows = half_rows - PADDING*2 - 1 # 1 for title
    to_ip_rows = max_y - half_rows - PADDING*2 - 1 # 1 for title

    horizontal_free_space = max_x - 50

    windows.main.border(0,0,0,0)
    windows.main.addstr(0, title_start, ip, curses.A_STANDOUT)
    windows.main.addstr(PADDING, PADDING, 'Received Data From:', curses.A_UNDERLINE)
    windows.main.addstr(PADDING+(rows // 2), PADDING, 'Sent Data To:', curses.A_UNDERLINE)

    format_str = '{:<20}{:>15}'
    for idx in range(0, from_ip_rows):
        if idx < len(from_ip):
            args = from_ip[idx]
        else:
            args = ('','')
        windows.main.addstr(PADDING+idx+1, PADDING, format_str.format(*args))

    for idx in range(0, to_ip_rows):
        if idx < len(to_ip):
            args = to_ip[idx]
        else:
            args = ('','')
        windows.main.addstr(PADDING*2+idx+from_ip_rows+2, PADDING, format_str.format(*args))
   

    bar_width = 12
    bar_padding = 2
    max_bars = (horizontal_free_space-bar_width) // (bar_width + bar_padding)

    if len(proto_sorted) > 0:
        max_bytes = proto_sorted[0][1]
        min_bytes = proto_sorted[min(max_bars-1, len(proto_sorted)-1)][1]

        if max_bytes != min_bytes:
            scale_max = max_bytes - min_bytes
        else:
            scale_max = max_bytes

        log_base = 10

        scale_max = math.log(scale_max, log_base)

    bar_y_free = max_y - PADDING*2 # free space for bar vertically
    cover = windows.main.derwin(max_y-PADDING*2, horizontal_free_space, PADDING, max_x-horizontal_free_space-PADDING)
    cover.bkgd(curses.A_NORMAL) # Remove old bar heights
    for x in range(0, min(max_bars, len(proto_sorted))):
        diff = max(1, proto_sorted[x][1] - min_bytes)
        bar_height = int((math.log(diff, log_base) / scale_max * (bar_y_free - PADDING)))
        bar_height = max(1, bar_height)

        bar_x = max_x - PADDING - horizontal_free_space + x * (bar_width + bar_padding)

        bar_start_y = bar_y_free - bar_height
        rect_win = windows.main.derwin(bar_height, bar_width, bar_start_y, bar_x)
        rect_win.bkgd(curses.A_STANDOUT)
        rect_win.noutrefresh()

        windows.main.addstr(max_y-PADDING*2, bar_x, proto_sorted[x][0][:bar_width])

def refresh_windows(windows):
    windows.header.noutrefresh()
    windows.asciiart.noutrefresh()
    windows.header_data.noutrefresh()
    windows.main.noutrefresh()
    curses.doupdate()

def print_callback(pkt):
    global pkt_queue

    pkt_queue.put_nowait(pkt)
#    if pkt.highest_layer not in layers:
#        win.addstr(count,0,pkt.highest_layer)
#        win.refresh()

class Windows:
    def __init__(self, stdscr):
        self.stdscr = stdscr

class Stats:
    def __init__(self):
        self.hosts = set()
        self.total_transfer = 0 # in bytes
        self.total_packets = 0

def window_resize(windows):
    windows.stdscr.clear()
    (max_y, max_x) = windows.stdscr.getmaxyx()
    header_win_y = 11

    if hasattr(windows, 'header'): windows.header.clear()
    windows.header = curses.newwin(header_win_y, max_x, 0, 0)

    if hasattr(windows, 'header_data'): windows.header_data.clear()
    windows.header_data = curses.newwin(header_win_y-PADDING*2, max_x-ascii_art_len-PADDING*2, PADDING, ascii_art_len + PADDING)

    if hasattr(windows, 'asciiart'): windows.asciiart.clear()
    windows.asciiart = curses.newwin(header_win_y-PADDING*2, ascii_art_len, PADDING, PADDING)

    height = max_y - header_win_y
    width = max_x
    begin_x = 0

    if hasattr(windows, 'main'): windows.asciiart.clear()
    windows.main = curses.newwin(height, width, header_win_y, begin_x)

    windows.main.border(0,0,0,0)

def screen_draw(windows, stats):
    global highlighted
    global src_or_dst
    level = 0
    most_recent_highlight = 0

    while True:
        ch = windows.stdscr.getch()
        do_clear = False
        do_update = False

        if ch == -1:
            pass
        elif ch == curses.KEY_RESIZE:
            window_resize(windows)
        elif ch in (curses.KEY_ENTER, 10) and level == 0:
            level += 1
            windows.main.clear()
        elif ch in (curses.KEY_BACKSPACE, 127) and level > 0:
            level -= 1
            do_clear = True
        elif ch in (cascii.SO, curses.KEY_DOWN) and level == 0:
            highlighted += 1
        elif ch in (cascii.DLE, curses.KEY_UP) and level == 0:
            highlighted -= 1
        elif ch in (curses.KEY_RIGHT, curses.KEY_LEFT) and level == 0:
            src_or_dst = not src_or_dst
            calculate_nlargest(windows)
            do_update = True

        update_headers(windows, stats)
        if level == 0:
            draw_byte_sort(windows, do_clear, do_update)
        elif level == 1:
            show_ip_details(windows, last_highlighted_val)
        refresh_windows(windows)

def main(stdscr):
    stdscr.clear()
    stdscr.nodelay(1)
    curses.noecho()
    curses.curs_set(0)

    windows = Windows(stdscr)
    window_resize(windows)

    stats = Stats()
    update_headers(windows, stats)
    
    thread1 = Thread(target=packet_maintain, args = (windows, stats))
    thread2 = Thread(target=screen_draw, args = (windows, stats))
    thread1.start()
    thread2.start()

    capture = pyshark.LiveCapture(interface='ens33')
    capture.apply_on_packets(print_callback)

def packet_lt(self, other):
    return xxhash.xxh32(str(self).encode('utf-8')).digest() < xxhash.xxh32(str(other).encode('utf-8')).digest()
pyshark.packet.packet.Packet.__lt__ = packet_lt

if __name__ == "__main__":
    curses.wrapper(main)
