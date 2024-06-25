import socket
import select
import threading
from collections import defaultdict
import re
import logging
import time

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 用于存储每个客户端的数据包序号
packet_sequence = defaultdict(int)

MAGIC = re.compile(b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78')

# 每秒最大数据包数量
MAX_PACKETS_PER_SECOND = 1000

# 单个数据包最大字节数
MAX_PACKET_SIZE = 1500

# 用于存储每个IP地址每秒发送的数据包数量
packet_counts = defaultdict(int)

# 用于存储每个IP的连接状态，包含端口号
connection_states = defaultdict(lambda: defaultdict(int))

# 用于存储每个IP的最后交互时间
last_interaction_time = defaultdict(lambda: defaultdict(float))

# 用于存储每个IP是否已经接收到服务端的数据
client_received_data = defaultdict(lambda: defaultdict(bool))


def is_valid_packet(data, addr):
    ip, port = addr

    # 检查数据包的长度
    if len(data) < 3:
        logging.warning(f"Received packet from {addr} is too short, data discarded.")
        return False

    # 检查数据包的类型
    packet_type = data[0]
    if packet_type not in list(range(256)):  # 允许所有类型的数据包
        logging.warning(f"Received packet from {addr} with invalid type {packet_type}, data discarded.")
        return False

    # 检查数据包的Magic字段
    if packet_type in [0x01, 0x02, 0x1c, 0x05, 0x06, 0x07, 0x08]:
        if packet_type in [0x01, 0x1c]: return False #直接拦截Motd 数据包
        if MAGIC.search(data) is None:
            logging.warning(f"Received packet from {addr} does not contain valid Magic, data discarded.")
            return False

    # 检查连接状态
    if connection_states[ip][port] == 0 and packet_type != 0x05:  # 如果还没有发送"Open Connection Request 1"
        logging.warning(f"Received packet from {addr} before 'Open Connection Request 1', data discarded.")
        return False

    # 更新连接状态
    if packet_type == 0x05:  # 如果是"Open Connection Request 1"
        if any(state == 1 for state in connection_states[ip].values()):
            logging.warning(f"Received 'Open Connection Request 1' from {addr} but IP {ip} is already connected, data discarded.")
            return False
        connection_states[ip][port] = 1

    # 更新最后交互时间
    last_interaction_time[ip][port] = time.time()

    # 如果数据包是有效的，返回True
    return True

def reset_packet_counts():
    packet_counts.clear()
    threading.Timer(1, reset_packet_counts).start()

def check_disconnections():
    current_time = time.time()
    for ip, ports in list(last_interaction_time.items()):
        for port, last_time in list(ports.items()):
            if client_received_data[ip][port] and current_time - last_time > 10:  # 超过10秒没有交互
                logging.info(f"Connection from {ip}:{port} timed out, clearing state.")
                del connection_states[ip][port]
                del last_interaction_time[ip][port]
                del client_received_data[ip][port]
                if not connection_states[ip]:
                    del connection_states[ip]
                if not last_interaction_time[ip]:
                    del last_interaction_time[ip]
                if not client_received_data[ip]:
                    del client_received_data[ip]
    threading.Timer(1, check_disconnections).start()

def print_stats(stats):
    for ip, data in stats.items():
        recv_kb, sent_kb = data['recv'] / 1024, data['sent'] / 1024
        logging.info(f"IP: {ip}, Received: {recv_kb:.2f}KB, Sent: {sent_kb:.2f}KB")
    stats.clear()
    threading.Timer(5, print_stats, args=(stats,)).start()

def forward_data(source_socket, target_address, stats):
    source_socket.setblocking(0)  # 设置为非阻塞模式

    addr_map = {}  # 用于存储每个客户端的地址和对应的转发套接字

    while True:
        sockets = [source_socket] + list(addr_map.values())
        ready_to_read, _, _ = select.select(sockets, [], [], 0.05)
        for sock in ready_to_read:
            if sock == source_socket:
                try:
                    data, addr = source_socket.recvfrom(65536)  # 将缓冲区大小设置为65536字节
                    if len(data) > MAX_PACKET_SIZE:
                        logging.warning("Received data is larger than buffer size, data discarded.")
                        continue
                    if not is_valid_packet(data, addr):
                        continue
                    if packet_counts[addr[0]] >= MAX_PACKETS_PER_SECOND:
                        logging.warning(f"Received too many packets from {addr[0]}, data discarded.")
                        continue
                    packet_counts[addr[0]] += 1
                    stats[addr[0]]['recv'] += len(data)
                    if addr not in addr_map:
                        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        forward_socket.setblocking(0)  # 设置为非阻塞模式
                        addr_map[addr] = forward_socket
                    addr_map[addr].sendto(data, target_address)
                except BlockingIOError:
                    continue  # 没有数据可读
            else:
                try:
                    data, addr = sock.recvfrom(65536)  # 将缓冲区大小设置为65536字节
                    if len(data) > MAX_PACKET_SIZE:
                        logging.warning("Received data is larger than buffer size, data discarded.")
                        continue
                    client_addr = [k for k, v in addr_map.items() if v == sock][0]
                    stats[client_addr[0]]['sent'] += len(data)
                    source_socket.sendto(data, client_addr)  # 将数据发送回原来的客户端
                    client_received_data[client_addr[0]][client_addr[1]] = True  # 标记客户端已接收到数据
                except BlockingIOError:
                    continue  # 没有数据可读

def main():
    try:
        source_port = input("请输入源端口号（默认19132）：") or "19132"
        target_port = input("请输入目标端口号（默认19134）：") or "19134"

        listen_address = ('0.0.0.0', int(source_port))
        target_address = ('127.0.0.1', int(target_port))

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(listen_address)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)  # 将接收缓冲区大小设置为65536字节

        stats = defaultdict(lambda: defaultdict(int))  # 使用defaultdict来存储每个IP的数据量

        logging.info(f"开始转发：{source_port} -> {target_port}")
        forward_thread = threading.Thread(target=forward_data, args=(server_socket, target_address, stats))
        forward_thread.start()

        threading.Timer(5, print_stats, args=(stats,)).start()  # 每5秒打印一次统计信息
        threading.Timer(1, reset_packet_counts).start()  # 每1秒重置数据包计数
        threading.Timer(1, check_disconnections).start()  # 每1秒检查断开连接

    except Exception as e:
        logging.error(f"发生错误：{e}")
        # 继续运行程序

if __name__ == "__main__":
    main()