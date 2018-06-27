import os
import logging
from datetime import date, datetime


class Logger:
    def __init__(self):
        """ Setup logging file path and formatting """
        self.default_filepath = os.path.dirname(os.getcwd())
        self.log_name = "ARCTICSWALLOW_DEBUG_" + str(date.today()) + ".log"
        self.log_name = os.path.join(self.default_filepath, "logs", self.log_name)
        log_directory = os.path.dirname(self.log_name)
        if not os.path.exists(log_directory):
            os.mkdir(log_directory)
        logging.basicConfig(filename=self.log_name, format='%(asctime)s %(levelname)s: %(message)s',
                            level=logging.DEBUG)

    # def write_log_file(self, event):
    #     """ Writes the event to the proper log file """
    #     time_now = datetime.now()
    #     with open(self.log_name, 'a') as log_file:
    #         if "\n" not in event:
    #             log_file.write(str(time_now))
    #         log_file.write(event)
