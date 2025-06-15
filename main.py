import socket
import concurrent.futures
import time
import sys


class PortScanner:
	def __init__(self, target: str, timeout: float = 2.0):
		self.target = target
		self.timeout = timeout
		self.tcp_results = {}
		self.udp_results = {}
		self.ip_address = None

	def validate_environment(self):
		try:
			socket.create_connection(("8.8.8.8", 53), timeout=3)
			return True
		except socket.error:
			try:
				socket.gethostbyname("google.com")
				return True
			except socket.error:
				print("Нет подключения к интернету")
				return False

	def resolve_target(self):
		try:
			self.ip_address = socket.gethostbyname(self.target)
			return self.ip_address
		except socket.gaierror as e:
			print(f"Ошибка разрешения имени: {e}\n"
			      f"Проверьте правильность имени '{self.target}' и подключение к DNS")
			return None
		except Exception as e:
			print(f"Неизвестная ошибка при разрешении имени: {e}")
			return None

	def scan_tcp_port(self, port: int):
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
				sock.settimeout(self.timeout)
				result = sock.connect_ex((self.ip_address, port))
				self.tcp_results[port] = result == 0
		except socket.timeout:
			self.tcp_results[port] = False
		except socket.error as e:
			print(f"Ошибка при сканировании TCP порта {port}: {e}")
			self.tcp_results[port] = False
		except Exception as e:
			print(f"Неизвестная ошибка при сканировании TCP порта {port}: {e}")
			self.tcp_results[port] = False

	def scan_udp_port(self, port: int):
		try:
			with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
				sock.settimeout(self.timeout)

				if sys.platform != 'win32':
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					try:
						sock.bind(('', 0))
					except OSError:
						pass

				sock.sendto(b'', (self.ip_address, port))

				try:
					data, _ = sock.recvfrom(1024)
					self.udp_results[port] = True
					return
				except ConnectionResetError:
					self.udp_results[port] = False
					return
				except OSError as e:
					if getattr(e, 'errno', None) in (101, 111):
						self.udp_results[port] = False
						return
					raise

		except socket.timeout:
			self.udp_results[port] = True
		except socket.error as e:
			print(f"Сетевая ошибка при сканировании UDP порта {port}: {e}")
			self.udp_results[port] = False
		except Exception as e:
			print(f"Критическая ошибка при сканировании UDP порта {port}: {e}")
			self.udp_results[port] = False

	def scan_ports(self, start_port: int, end_port: int, max_workers: int = 100):
		if not self.validate_environment():
			return {}, {}

		if not self.resolve_target():
			return {}, {}

		ports = range(start_port, end_port + 1)

		try:
			with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
				executor.map(self.scan_tcp_port, ports)

				for port_chunk in [ports[i:i + 50] for i in range(0, len(ports), 50)]:
					executor.map(self.scan_udp_port, port_chunk)
					time.sleep(0.5)

		except KeyboardInterrupt:
			print("\nСканирование прервано пользователем")
			return self.tcp_results, self.udp_results
		except Exception as e:
			print(f"Ошибка во время сканирования: {e}")
			return self.tcp_results, self.udp_results

		return self.tcp_results, self.udp_results


def main():
	try:
		target = input("Введите хост (IP или доменное имя): ").strip()
		if not target:
			raise ValueError("Не указан хост")

		try:
			start_port = int(input("Начальный порт (1-65535): "))
			end_port = int(input("Конечный порт (1-65535): "))
			if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
				raise ValueError("Порты должны быть в диапазоне 1-65535")
			if start_port > end_port:
				raise ValueError("Начальный порт должен быть меньше конечного")
		except ValueError as e:
			print(f"Ошибка ввода: {e}")
			return

		scanner = PortScanner(target, timeout=2.0)
		print(f"\nСканирование {target} с порта {start_port} по {end_port}...")

		start_time = time.time()
		tcp_results, udp_results = scanner.scan_ports(start_port, end_port)
		elapsed = time.time() - start_time

		print("\nРезультаты сканирования:")
		print("TCP порты:")
		for port, is_open in sorted(tcp_results.items()):
			if is_open:
				print(f"  {port}: OPEN")

		print("\nUDP порты:")
		for port, is_open in sorted(udp_results.items()):
			if is_open:
				print(f"  {port}: OPEN")
			else:
				print(f"  {port}: CLOSE")

		print(f"\nСканирование завершено за {elapsed:.2f} секунд")

	except KeyboardInterrupt:
		print("\nПрограмма прервана пользователем")
	except Exception as e:
		print(f"\nНеожиданная ошибка: {e}")


if __name__ == "__main__":
	main()