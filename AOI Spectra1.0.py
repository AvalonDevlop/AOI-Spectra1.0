import argparse
import asyncio
import configparser
import datetime
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import psutil
from aioping import ping as async_ping
from scapy.all import ARP, Ether, srp

# 设置日志
log_file = 'network_scan.log'
logging.basicConfig(
	level=logging.DEBUG,
	format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
	handlers=[
		logging.FileHandler(log_file, mode='a', encoding='utf-8'),  # 指定编码为 UTF-8
		logging.StreamHandler()  # 同时输出到控制台
	]
)

# 数据库连接
conn = sqlite3.connect('network_scan.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    mac TEXT,
                    hostname TEXT,
                    state TEXT,
                    open_ports TEXT,
                    services TEXT,
                    parent_ip TEXT,
                    depth INTEGER,
                    timestamp DATETIME)''')
conn.commit()


class NetworkScanner:
	def __init__(self, config):
		self.config = config
		self.ip_range = config['Network']['ip_range']
		self.max_depth = int(config['Network']['max_depth'])
		self.timeout = float(config['Network']['timeout'])
		self.active_hosts = None
		self.executor = ThreadPoolExecutor(max_workers=int(config['Performance']['max_workers']))
		self.logger = logging.getLogger(self.__class__.__name__)

	async def ping_host(self, ip):
		"""Ping a single host and return True if it's active."""
		try:
			delay = await async_ping(ip, timeout=self.timeout)
			self.logger.info(f"Host {ip} is active (ping delay: {delay:.2f} ms)")
			return True
		except TimeoutError:
			self.logger.info(f"Host {ip} is inactive (timeout)")
			return False
		except Exception as e:
			self.logger.error(f"Error pinging {ip}: {e}")
			return False

	def arp_scan(self, ip_range):
		"""Scan the network for active hosts using ARP request."""
		self.logger.info(f"Scanning network: {ip_range}")

		# 构造 ARP 请求包
		arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip_range)

		# 发送 ARP 请求并接收响应
		result = srp(arp_request, timeout=2, verbose=False)[0]

		devices = []
		for sent, received in result:
			devices.append({'ip': received.psrc, 'mac': received.hwsrc})
			self.logger.info(f"Found device: IP={received.psrc}, MAC={received.hwsrc}")

		return pd.DataFrame(devices, columns=['IP', 'MAC'])

	async def scan_network(self, ip_range, parent_ip=None, current_depth=0):
		"""Scan the network for active hosts using both ICMP and ARP."""
		if current_depth >= self.max_depth:
			return []

		network = ipaddress.ip_network(ip_range, strict=False)
		tasks = [self.ping_host(str(ip)) for ip in network.hosts()]
		results = await asyncio.gather(*tasks)

		# Extract active hosts from ICMP ping
		active_ips = [str(ip) for ip, result in zip(network.hosts(), results) if result]

		# Perform ARP scan to get more accurate results
		arp_results = self.arp_scan(ip_range)
		arp_ips = set(arp_results['IP'])

		# Combine results from ICMP and ARP
		all_active_ips = list(set(active_ips + list(arp_ips)))
		data = []
		for ip in all_active_ips:
			mac = self.get_mac_address(ip)
			hostname = self.get_hostname(ip)
			open_ports = await self.port_scan(ip)
			services = await self.get_service_versions(ip, open_ports)
			data.append(
				[ip, hostname, 'up', mac, open_ports, services, parent_ip, current_depth, datetime.datetime.now()])

		# Save to database
		cursor.executemany('''INSERT INTO hosts (ip, mac, hostname, state, open_ports, services, parent_ip, depth, timestamp)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
		conn.commit()

		self.logger.info(f"Scanned network: {ip_range}, found {len(data)} active hosts.")
		return data

	def get_mac_address(self, ip):
		"""Get the MAC address of an IP using ARP request."""
		try:
			arp_request = ARP(pdst=ip)
			broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
			packet = broadcast / arp_request
			result = srp(packet, timeout=1, verbose=False)[0]
			return result[0][1].hwsrc if result else None
		except Exception as e:
			self.logger.error(f"Error getting MAC address for {ip}: {e}")
			return None

	def get_hostname(self, ip):
		"""Get the hostname of an IP using reverse DNS lookup."""
		try:
			return socket.gethostbyaddr(ip)[0]
		except Exception as e:
			self.logger.error(f"Error getting hostname for {ip}: {e}")
			return None

	async def port_scan(self, ip, ports=None):
		"""Scan a single host for open ports."""
		if ports is None:
			ports = [int(port) for port in self.config['Ports'].get('default_ports', '22,80,443').split(',')]

		open_ports = []
		for port in ports:
			try:
				reader, writer = await asyncio.open_connection(ip, port)
				open_ports.append(port)
				writer.close()
				await writer.wait_closed()
				self.logger.info(f"Found open port {port} on {ip}")
			except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
				pass
			except Exception as e:
				self.logger.error(f"Error scanning {ip}:{port}: {e}")

		return open_ports

	async def get_service_versions(self, ip, open_ports):
		"""Get service versions for open ports using banner grabbing."""
		services = {}
		for port in open_ports:
			try:
				reader, writer = await asyncio.open_connection(ip, port)
				writer.write(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
				await writer.drain()
				response = await reader.read(1024)
				services[port] = response.decode().strip()
				writer.close()
				await writer.wait_closed()
			except Exception as e:
				self.logger.error(f"Error getting service version for {ip}:{port}: {e}")

		return services

	async def deep_traverse(self, ip, current_depth=0):
		"""Recursively traverse the network to find deeper layers of servers."""
		if current_depth >= self.max_depth:
			return

		# Scan the host's network range (e.g., based on its subnet mask)
		try:
			network = ipaddress.ip_network(f"{ip}/24", strict=False)
			await self.scan_network(str(network), parent_ip=ip, current_depth=current_depth + 1)
		except Exception as e:
			self.logger.error(f"Error traversing network for {ip}: {e}")

	async def analyze_data(self):
		"""Analyze and detect potential security threats."""
		cursor.execute("SELECT * FROM hosts")
		rows = cursor.fetchall()
		if not rows:
			self.logger.warning("No data to analyze.")
			return

		df = pd.DataFrame(rows, columns=['id', 'ip', 'mac', 'hostname', 'state', 'open_ports', 'services', 'parent_ip',
		                                 'depth', 'timestamp'])
		print("Network Analysis Summary:")
		print(df.describe())

		# Detect anomalies based on open ports and services
		for index, row in df.iterrows():
			ip = row['ip']
			open_ports = json.loads(row['open_ports']) if row['open_ports'] else []
			services = json.loads(row['services']) if row['services'] else {}

			# Rule 1: Detect unusual number of open ports
			if len(open_ports) > int(self.config['Security']['max_open_ports']):
				self.logger.warning(f"Unusual number of open ports detected on {ip}: {open_ports}")
				self.block_ip(ip, "Unusual number of open ports detected.")
				self.send_warning(ip, "Unusual number of open ports detected.")

			# Rule 2: Detect unknown or suspicious services
			for port, service in services.items():
				if "unknown" in service.lower() or "unauthorized" in service.lower():
					self.logger.warning(f"Suspicious service detected on {ip}:{port}: {service}")
					self.block_ip(ip, f"Suspicious service detected on port {port}.")
					self.send_warning(ip, f"Suspicious service detected on port {port}.")

			# Rule 3: Detect common attack patterns (e.g., port scans, SYN floods)
			if self.detect_attack_patterns(ip):
				self.logger.warning(f"Potential attack pattern detected on {ip}.")
				self.block_ip(ip, "Potential attack pattern detected.")
				self.send_warning(ip, "Potential attack pattern detected.")

		# Monitor system resources for unusual activity
		self.monitor_system_resources()

	def detect_attack_patterns(self, ip):
		"""Detect common attack patterns such as port scans or SYN floods."""
		try:
			connections = psutil.net_connections()
			recent_connections = [conm for conm in connections if conm.laddr.ip == ip and conm.status == 'ESTABLISHED']
			if len(recent_connections) > int(self.config['Security']['max_connections']):
				self.logger.warning(f"Potential port scan or SYN flood detected on {ip}.")
				return True
		except Exception as e:
			self.logger.error(f"Error detecting attack patterns on {ip}: {e}")

		return False

	def monitor_system_resources(self):
		"""Monitor system resources for unusual activity."""
		cpu_usage = psutil.cpu_percent(interval=1)
		memory_usage = psutil.virtual_memory().percent
		disk_usage = psutil.disk_usage('/').percent

		self.logger.info(f"System resource usage: CPU={cpu_usage}%, Memory={memory_usage}%, Disk={disk_usage}%")

		# Rule 1: High CPU usage
		if cpu_usage > int(self.config['Security']['max_cpu_usage']):
			self.logger.warning(f"High CPU usage detected: {cpu_usage}%")
			self.send_warning("System", "High CPU usage detected.")

		# Rule 2: High memory usage
		if memory_usage > int(self.config['Security']['max_memory_usage']):
			self.logger.warning(f"High memory usage detected: {memory_usage}%")
			self.send_warning("System", "High memory usage detected.")

		# Rule 3: High disk usage
		if disk_usage > int(self.config['Security']['max_disk_usage']):
			self.logger.warning(f"High disk usage detected: {disk_usage}%")
			self.send_warning("System", "High disk usage detected.")

	def block_ip(self, ip, reason):
		"""Block the specified IP address using the firewall."""
		self.logger.warning(f"Blocking IP {ip} due to: {reason}")
		if os.name == 'nt':  # Windows
			command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
		else:  # Linux
			command = f'iptables -A INPUT -s {ip} -j DROP'

		try:
			subprocess.run(command, shell=True, check=True)
			self.logger.info(f"Successfully blocked IP {ip}.")
		except subprocess.CalledProcessError as e:
			self.logger.error(f"Failed to block IP {ip}: {e}")

	def unblock_ip(self, ip):
		"""Unblock the specified IP address using the firewall."""
		self.logger.info(f"Unblocking IP {ip}.")
		if os.name == 'nt':  # Windows
			command = f'netsh advfirewall firewall delete rule name="Block {ip}"'
		else:  # Linux
			command = f'iptables -D INPUT -s {ip} -j DROP'

		try:
			subprocess.run(command, shell=True, check=True)
			self.logger.info(f"Successfully unblocked IP {ip}.")
		except subprocess.CalledProcessError as e:
			self.logger.error(f"Failed to unblock IP {ip}: {e}")

	def send_warning(self, target, message):
		"""Send a warning message to the facility."""
		warning_message = f"AOI Spectra监测到您的设备有入侵风险: {message}"
		self.logger.warning(warning_message)
		print(f"Warning sent to {target}: {warning_message}")

	def monitor_traffic(self):
		"""Monitor network traffic and bandwidth usage."""
		while True:
			net_io = psutil.net_io_counters(pernic=True)
			for interface, stats in net_io.items():
				bytes_sent = stats.bytes_sent
				bytes_recv = stats.bytes_recv

				# 忽略没有流量的接口
				if bytes_sent == 0 and bytes_recv == 0:
					continue

				# Log traffic data to console and file
				log_entry = {
					"timestamp": time.time(),
					"interface": interface,
					"bytes_sent": bytes_sent,
					"bytes_recv": bytes_recv
				}
				self.logger.info(json.dumps(log_entry))


			time.sleep(1)

	async def take_countermeasures(self, ip):
		"""Take countermeasures to help the device recover from an intrusion."""
		self.logger.warning(f"Taking countermeasures for IP {ip}.")

		# Step 1: Block the IP address to prevent further attacks
		self.block_ip(ip, "Taking countermeasures.")

		# Step 2: Close any suspicious open ports
		cursor.execute("SELECT open_ports FROM hosts WHERE ip=?", (ip,))
		row = cursor.fetchone()
		if row:
			open_ports = json.loads(row[0]) if row[0] else []
			for port in open_ports:
				self.close_port(ip, port)

		# Step 3: Restart affected services (if applicable)
		self.restart_services(ip)

		# Step 4: Send a warning to the facility
		self.send_warning(ip, "Countermeasures taken to mitigate the intrusion.")

	def close_port(self, ip, port):
		"""Close a specific port on the device."""
		self.logger.info(f"Closing port {port} on {ip}.")
		if os.name == 'nt':  # Windows
			command = f'netsh advfirewall firewall add rule name="Close Port {port}" protocol=TCP dir=in localport={port} action=block'
		else:  # Linux
			command = f'iptables -A INPUT -p tcp --dport {port} -j DROP'

		try:
			subprocess.run(command, shell=True, check=True)
			self.logger.info(f"Successfully closed port {port} on {ip}.")
		except subprocess.CalledProcessError as e:
			self.logger.error(f"Failed to close port {port} on {ip}: {e}")

	def restart_services(self, ip):
		"""Restart affected services on the device."""
		self.logger.info(f"Restarting services on {ip}.")

	# Here you can implement logic to restart specific services on the device.
	# For example, you can use SSH to connect to the device and execute commands.

	async def main_loop(self):
		"""Main loop for continuous monitoring and analysis."""
		while True:
			await self.scan_network(self.ip_range)
			cursor.execute("SELECT DISTINCT ip FROM hosts WHERE depth < ?", (self.max_depth,))
			parent_ips = [row[0] for row in cursor.fetchall()]

			# 对每个找到的主机进行递归扫描
			tasks = [self.deep_traverse(ip, current_depth=1) for ip in parent_ips]
			await asyncio.gather(*tasks)

			# 分析数据并检测入侵风险
			await self.analyze_data()

			# 等待 60 秒后再次扫描
			await asyncio.sleep(int(self.config['Performance']['scan_interval']))

	async def export_data(self, output_format='csv'):
		"""Export scanned data to a file in the specified format."""
		cursor.execute("SELECT * FROM hosts")
		rows = cursor.fetchall()
		if not rows:
			self.logger.warning("No data to export.")
			return

		df = pd.DataFrame(rows, columns=['id', 'ip', 'mac', 'hostname', 'state', 'open_ports', 'services', 'parent_ip',
		                                 'depth', 'timestamp'])

		if output_format == 'csv':
			df.to_csv('network_scan.csv', index=False)
			self.logger.info("Data exported to network_scan.csv.")
		elif output_format == 'json':
			with open('network_scan.json', 'w') as f:
				json.dump(df.to_dict(orient='records'), f, indent=4)
			self.logger.info("Data exported to network_scan.json.")
		else:
			self.logger.error(f"Unsupported output format: {output_format}")


async def main():
	# 解析命令行参数
	parser = argparse.ArgumentParser(description="Network Scanner and Monitor")
	parser.add_argument('--config', default='config.ini', help='Path to configuration file')
	parser.add_argument('--output-format', choices=['csv', 'json'], default='csv',
	                    help='Output format for exported data')
	args = parser.parse_args()
	# 加载配置文件
	config = configparser.ConfigParser()
	config.read(args.config)

	# 初始化网络扫描器
	scanner = NetworkScanner(config)

	# 启动网络流量监控
	asyncio.create_task(asyncio.to_thread(scanner.monitor_traffic))

	try:
		# 启动主循环
		await scanner.main_loop()

	finally:
		# 确保在程序结束时关闭线程池
		if hasattr(scanner, 'executor') and scanner.executor is not None:
			scanner.executor.shutdown(wait=True)

		# 取消所有未完成的任务
		for task in asyncio.all_tasks():
			if task is not asyncio.current_task():
				task.cancel()

		# 等待所有任务完成
		await asyncio.gather(*asyncio.all_tasks(), return_exceptions=True)

		# 导出数据
		await scanner.export_data(output_format=args.output_format)


if __name__ == "__main__":
	asyncio.run(main())

#log文件字符查看:
# Get-Content 'D:\AOI Chip\AOI NEXT\AOI Spectra\network_scan.log' | Measure-Object -Character