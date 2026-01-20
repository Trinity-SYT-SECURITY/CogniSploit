import logging
from colorama import Fore, Style, init
import sqlite3

# Initialize colorama
init()

class Logger:
    colors = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'blue': Fore.BLUE,
        'yellow': Fore.YELLOW,
        'magenta': Fore.MAGENTA,
        'cyan': Fore.CYAN,
        'white': Fore.WHITE,
        'black': Fore.BLACK,
        'light_red': Fore.LIGHTRED_EX,
        'light_green': Fore.LIGHTGREEN_EX,
        'light_blue': Fore.LIGHTBLUE_EX,
        'light_yellow': Fore.LIGHTYELLOW_EX,
        'light_magenta': Fore.LIGHTMAGENTA_EX,
        'light_cyan': Fore.LIGHTCYAN_EX,
        'light_white': Fore.LIGHTWHITE_EX,
        'dark_gray': Fore.LIGHTBLACK_EX,
        'dim': Style.DIM,
        'normal': Style.NORMAL,
        'bright': Style.BRIGHT
    }

    def __init__(self, name='app'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        self.logger.addHandler(handler)

    def clear_database(self):
        """Clear all entries in the error_logs table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM error_logs")
        conn.commit()
        conn.close()

    def _log_to_db(self, level, msg):
        """Log a message to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO error_logs (level, message) VALUES (?, ?)",
            (level, msg)
        )
        conn.commit()
        conn.close()

    def info(self, message, color='white'):
        color_code = self.colors.get(color, Fore.WHITE)
        self.logger.info(f"{color_code}{message}{Style.RESET_ALL}")

    def warning(self, message, color='yellow'):
        color_code = self.colors.get(color, Fore.YELLOW)
        self.logger.warning(f"{color_code}{message}{Style.RESET_ALL}")

    def error(self, message, color='red'):
        color_code = self.colors.get(color, Fore.RED)
        self.logger.error(f"{color_code}{message}{Style.RESET_ALL}")

    def debug(self, message, color='cyan'):
        color_code = self.colors.get(color, Fore.CYAN)
        self.logger.debug(f"{color_code}{message}{Style.RESET_ALL}")