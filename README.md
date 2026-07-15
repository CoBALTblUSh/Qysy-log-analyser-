Q-SYS Log Dashboard
===================

WHAT IT DOES
------------
This local Python dashboard opens Q-SYS .qsyslog diagnostic archives and makes them easier to read.

It includes:
- Device, firmware, serial number, design-status, fan, and temperature cards
- Q-SYS-specific findings for HDMI, SCDC, MMCM, HDCP, encoder stream-up/down, and thermal faults
- Searchable/filterable event table
- Raw archive file browser
- Support for .qsyslog, ZIP, TAR/GZIP, normal log files, and extracted directories
- No cloud connection and no external Python packages

PYCHARM SETUP
-------------
1. Create or open any Python project in PyCharm.
2. Add qsys_log_dashboard.py to the project.
3. Use Python 3.10 or newer.
4. Right-click the script and choose Run 'qsys_log_dashboard'.
5. Select your .qsyslog file when the file chooser appears.
6. Your default browser will open the dashboard.

You do not need to install packages with pip.

OPTIONAL RUN ARGUMENT
---------------------
To load the same file immediately, edit the PyCharm Run Configuration and put its path in "Script parameters":

    /path/to/nv-21-hu.qsyslog

TERMINAL EXAMPLES
-----------------
    python qsys_log_dashboard.py
    python qsys_log_dashboard.py "/path/to/device.qsyslog"
    python qsys_log_dashboard.py "/path/to/device.qsyslog" --port 8765

STOPPING IT
-----------
Stop the PyCharm run process or press Ctrl+C in the terminal.

SECURITY
--------
The server listens only on 127.0.0.1 by default. The archive is extracted to a temporary local folder and removed when the app exits.
