import customtkinter as ctk
import socket
import threading

# Настройки темы интерфейса
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PortScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Security Scanner")
        self.geometry("600x500")
        self.resizable(False, False)

        # Переменная для контроля остановки сканирования
        self.is_scanning = False

        # ==========================================
        # ИНТЕРФЕЙС (UI ЭЛЕМЕНЕНТЫ)
        # ==========================================

        # Заголовок
        self.title_label = ctk.CTkLabel(self, text="NETWORK PORT SCANNER", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=15)

        # Фрейм для ввода данных
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(pady=10, padx=20, fill="x")

        # Ввод IP
        self.ip_label = ctk.CTkLabel(self.input_frame, text="Target IP / Host:")
        self.ip_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.ip_entry = ctk.CTkEntry(self.input_frame, placeholder_text="127.0.0.1", width=150)
        self.ip_entry.insert(0, "127.0.0.1") # Дефолтный локальный адрес
        self.ip_entry.grid(row=0, column=1, padx=10, pady=10)

        # Ввод портов
        self.port_label = ctk.CTkLabel(self.input_frame, text="Ports (Start - End):")
        self.port_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        
        self.start_port_entry = ctk.CTkEntry(self.input_frame, placeholder_text="1", width=60)
        self.start_port_entry.insert(0, "1")
        self.start_port_entry.grid(row=0, column=3, padx=5, pady=10)

        self.end_port_entry = ctk.CTkEntry(self.input_frame, placeholder_text="1024", width=60)
        self.end_port_entry.insert(0, "100") # Для теста сканируем первые 100 портов
        self.end_port_entry.grid(row=0, column=4, padx=5, pady=10)

        # Кнопка запуска
        self.scan_button = ctk.CTkButton(self, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack(pady=15)

        # Прогресс-бар
        self.progress_bar = ctk.CTkProgressBar(self, width=400)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)

        # Поле вывода результатов
        self.result_text = ctk.CTkTextbox(self, width=540, height=250, font=ctk.CTkFont(family="Courier", size=13))
        self.result_text.pack(pady=15, padx=20)
        self.result_text.configure(state="disabled")

    # ==========================================
    # ЛОГИКА СКАНИРОВАНИЯ
    # ==========================================

    def log_message(self, message):
        """Безопасное добавление текста в консоль интерфейса"""
        self.result_text.configure(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.configure(state="disabled")

    def start_scan_thread(self):
        """Запуск сканирования в отдельном потоке, чтобы интерфейс не зависал"""
        if self.is_scanning:
            self.is_scanning = False
            self.scan_button.configure(text="Start Scan", fg_color=["#3B8ED0", "#1F6AA5"])
            return

        target_ip = self.ip_entry.get().strip()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
        except ValueError:
            self.log_message("[!] Error: Ports must be integers.")
            return

        if start_port < 1 or end_port > 65535 or start_port > end_port:
            self.log_message("[!] Error: Invalid port range (1-65535).")
            return

        # Меняем состояние кнопки на "Стоп"
        self.is_scanning = True
        self.scan_button.configure(text="Stop Scan", fg_color="#D32F2F")
        
        # Очищаем текстовое поле
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.configure(state="disabled")
        
        self.log_message(f"[*] Resolving target: {target_ip}")
        self.log_message(f"[*] Scanning started on ports {start_port}-{end_port}...\n")

        # Запускаем фоновый поток, чтобы окно не превращалось в "Не отвечает"
        scan_thread = threading.Thread(target=self.run_port_scan, args=(target_ip, start_port, end_port))
        scan_thread.daemon = True
        scan_thread.start()

    def run_port_scan(self, ip, start_port, end_port):
        """Основной цикл сканирования портов"""
        try:
            # Превращаем доменное имя в IP, если ввели имя (например, localhost)
            target_host = socket.gethostbyname(ip)
        except socket.gaierror:
            self.log_message("[!] Error: Could not resolve hostname.")
            self.finalize_scan()
            return

        total_ports = end_port - start_port + 1
        open_ports_count = 0

        for index, port in enumerate(range(start_port, end_port + 1)):
            if not self.is_scanning:
                self.log_message("\n[!] Scan stopped by user.")
                break

            # Обновляем прогресс-бар в интерфейсе
            progress = (index + 1) / total_ports
            self.progress_bar.set(progress)

            # Пытаемся подключиться к порту
            # AF_INET = IPv4, SOCK_STREAM = TCP протокол
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) # Ждем ответ не больше 0.5 секунды
            
            # connect_ex возвращает 0, если соединение успешно (порт открыт)
            result = s.connect_ex((target_host, port))
            
            if result == 0:
                try:
                    # Пробуем определить имя службы, которая висит на порту (например, 80 -> HTTP)
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "unknown service"
                
                self.log_message(f"[+] Port {port}: OPEN ({service})")
                open_ports_count += 1
                
            s.close()

        if self.is_scanning:
            self.log_message(f"\n[+] Scan finished. Found {open_ports_count} open ports.")
        
        self.finalize_scan()

    def finalize_scan(self):
        """Возвращаем интерфейс в исходное состояние"""
        self.is_scanning = False
        self.scan_button.configure(text="Start Scan", fg_color=["#3B8ED0", "#1F6AA5"])

if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()