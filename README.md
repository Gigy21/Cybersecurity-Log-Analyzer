Cybersecurity Log Analyzer
About the Project

Cybersecurity Log Analyzer is a Python command-line tool that helps identify suspicious login activity by analyzing authentication log files.

I created this project as my CS50P Final Project. The main idea was to build a program that can read login records, keep track of successful and failed attempts, and identify IP addresses that may be involved in brute-force activity.

The program also creates reports so users can easily review the results and see which IP addresses have an unusual number of failed login attempts.

Features

The program includes the following features:

Reads authentication logs from a text file.
Checks whether timestamps, IP addresses, and login statuses are valid.
Keeps track of successful and failed login attempts.
Counts failed login attempts for each IP address.
Flags IP addresses that reach a specified number of failed attempts.
Allows users to change the detection threshold.
Displays a summary of the analysis in the terminal.
Saves the results in TXT and CSV formats.
Handles invalid log entries and file-related errors.
Project Files

The project contains the following files:

project.py — Contains the main program and the functions used to analyze log files.
test_project.py — Contains automated tests written with pytest.
sample_logs.txt — A sample authentication log file for testing the program.
requirements.txt — Lists the Python package required for testing.
README.md — Provides information about the project and explains how to use it.
Requirements

Before running the program, make sure you have:

Python 3.10 or newer installed.
pip installed on your computer.
Installation
1. Download the project

You can clone the repository from GitHub:

git clone https://github.com/Gigy21/Cybersecurity-Log-Analyzer.git


You can also download the project as a ZIP file and extract it.

2. Open the project folder

Open your terminal or command prompt and navigate to the folder containing the project files.

3. Install the required package

Run the following command:

bash
pip install -r requirements.txt


This installs pytest, which is used to run the automated tests.

How to Use the Program
1. Prepare an authentication log file

The program expects log entries to follow this format:

text
YYYY-MM-DD HH:MM:SS STATUS IP_ADDRESS


Each line should contain:

A date in YYYY-MM-DD format.
A time in HH:MM:SS format.
A login status: FAILED or SUCCESS.
A valid IPv4 or IPv6 address.

Here is an example:

text
2026-11-18 10:00:00 FAILED 192.168.1.10
2026-11-18 10:01:00 FAILED 192.168.1.10
2026-11-18 10:02:00 FAILED 192.168.1.10
2026-11-18 10:03:00 SUCCESS 192.168.1.20
2026-11-18 10:04:00 FAILED 10.0.0.5


You can use the included sample_logs.txt file or create your own file using the same format.

2. Run the program

To analyze the sample log file, use:

bash
python project.py sample_logs.txt


After running the command, the program will:

Read the log file.
Check the entries and ignore invalid ones according to the program's validation rules.
Count successful and failed login attempts.
Check how many failed attempts came from each IP address.
Identify IP addresses that have reached the detection threshold.
Display the results in the terminal.
Save the report as a TXT file and export the results to CSV.
3. Change the detection threshold

By default, the program flags an IP address when it has 5 or more failed login attempts.

You can change this number using the --threshold argument.

For example:

bash
python project.py sample_logs.txt --threshold 3


With this setting, an IP address will be flagged after at least 3 failed login attempts.

You can also increase the threshold:

bash
python project.py sample_logs.txt --threshold 10


The threshold must be a positive integer.

4. Choose a CSV output filename

By default, the CSV report is saved as security_report.csv.

If you want to use a different filename, you can provide it with the --output argument:

bash
python project.py sample_logs.txt --output my_report.csv


You can also combine the threshold and output arguments:

bash
python project.py sample_logs.txt --threshold 3 --output my_report.csv

5. Check the generated reports

After the analysis is complete, the program generates two reports:

security_report.txt — Contains a readable summary of the analysis.
security_report.csv — Contains login activity information for each IP address.

The CSV report can be opened with Microsoft Excel, Google Sheets, or any other application that supports CSV files.

An example of the CSV output looks like this:

csv
IP Address,Failed Attempts,Successful Logins,Suspicious
192.168.1.10,5,0,YES
192.168.1.20,0,1,NO
10.0.0.5,1,1,NO


This makes it easier to compare login activity and find IP addresses with repeated failed attempts.

Running the Tests

I also included a test file to check whether the main parts of the program work correctly.

To run the tests, first make sure pytest is installed:

bash
pip install -r requirements.txt


Then run:

bash
pytest -v


The tests cover the following parts of the program:

Parsing and validating log entries.
Handling invalid timestamps and IP addresses.
Loading log files.
Counting login activity.
Detecting repeated failed login attempts.
Generating security reports.
Exporting results to CSV.
Troubleshooting

Here are a few common problems you might encounter while using the program.

File not found

Make sure the log file exists and that you are running the command from the correct directory. If the file is somewhere else, provide its full or relative path.

Invalid log entries

Check that each line follows the required format. Make sure the date, time, status, and IP address are valid.

Python is not recognized

Make sure Python is installed and added to your system PATH. Depending on your operating system, you may need to use python3 instead of python.

pytest is not recognized

Try installing pytest directly:

bash
python -m pip install pytest


Then run the tests using:

bash
python -m pytest -v

How the Program Works

The project uses several built-in Python modules to handle different tasks:

argparse is used to read command-line arguments, such as the log file path and detection threshold.
csv is used to export the analysis results.
ipaddress checks whether the IP addresses in the log file are valid.
collections.Counter helps count failed login attempts.
collections.defaultdict is used to organize login activity by IP address.
datetime is used to validate dates and timestamps.

I separated the program into different functions so that each part has its own responsibility. This also makes the code easier to test and understand.

Limitations

This project is mainly intended for learning and practicing Python. It is not a complete security monitoring system.

The program only analyzes log files that are provided by the user. It does not monitor live network traffic, block suspicious IP addresses, or prevent unauthorized access.

Another limitation is the way brute-force activity is detected. The program counts the total number of failed login attempts from each IP address, without considering how much time passed between attempts.

For example, five failed attempts within one minute and five failed attempts over several days are treated the same way.

Because of this, a flagged IP address should be considered potentially suspicious, not automatically treated as an attacker.

Video Demonstration

You can watch the project demonstration here:

https://youtu.be/YeQYH1Hd1fY

Author

Created by Gigi Saridze

Harvard CS50P — Introduction to Programming with Python.

Project: Cybersecurity Log Analyzer

Programming Language: Python
