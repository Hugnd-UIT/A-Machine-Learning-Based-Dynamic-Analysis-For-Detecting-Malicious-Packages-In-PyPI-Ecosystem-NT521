# QUT-DV25 Dataset

This is **QUT-DV25** dataset, a comprehensive dynamic behavioral dataset of **14,271 Python packages** (7,127 malicious and 7,144 benign) gathered during installation.

---

## Overview

The dataset is partitioned into two primary collections:

```
dataset/
├── QUT-DV25-Raw/
│   ├── QUT-DV25-Benign/ 
│   └── QUT-DV25-Malicious/
│
└── QUT-DV25-Processed/    
    ├── QUT-DV25-Filetop-Traces/
    ├── QUT-DV25-Install-Traces/
    ├── QUT-DV25-Opensnoop-Traces/
    ├── QUT-DV25-Pattern-Traces/
    ├── QUT-DV25-SysCall-Traces/
    └── QUT-DV25-TCP-Traces/
```

---

## Why choose

Traditional security defenses for open-source package repositories predominantly rely on metadata inspection and static code analysis. However, modern supply chain attacks in the PyPI ecosystem easily bypass these static mechanisms. Attackers frequently conceal malicious logic using advanced code obfuscation, base64 encoding, dynamic reflection, and runtime string execution via `eval()` or `exec()`. Furthermore, malicious packages often download secondary payloads or execute rogue commands directly during the installation phase (e.g., within `setup.py` hooks), leaving no trace in static source scans. To counter this, real-time dynamic monitoring at the Linux kernel level captures fundamental behavioral telemetry across six complementary categories that adversaries cannot disguise.

At the file and directory access level, **Opensnoop Traces** detect unauthorized path traversals. While benign packages strictly confine their operations to the active virtual environment and standard Python runtime directories (`/usr/lib`), malicious samples actively reconnoiter sensitive system locations, attempting to exfiltrate SSH private keys from `/root/.ssh/` or `/home/<user>/.ssh/`, harvest system credentials from `/etc/passwd`, or drop hidden shell scripts into temporary directories like `/tmp/`. Complementing this, **Filetop Traces** observe abnormal file I/O volumes and identify unauthorized background processes. Whereas legitimate installations exhibit predictable read/write ratios driven entirely by `pip`, malicious packages spawn rogue utility processes such as `bash`, `curl`, or `wget` to tamper with system files or read sensitive files in bulk prior to exfiltration.

From a networking perspective, **TCP Traces** provide crucial visibility into command-and-control (C2) communication and data exfiltration. Benign packages exclusively establish outbound connections over standard HTTPS (port 443) to official PyPI distribution domains (`files.pythonhosted.org`). In stark contrast, malicious packages initiate connections to arbitrary external IP addresses, connect through suspicious non-standard ports (such as IRC port 6667 or raw TCP sockets), and maintain atypical state transitions associated with reverse shells and credential broadcasting. Concurrently, **Installation Traces** inspect the dependency resolution process, exposing dependency confusion and typosquatting attacks where altered dependencies trigger installation mismatches or pull malicious secondary packages down the dependency graph.

Finally, operating system interactions and temporal execution flows are captured through **SysCall Traces** and **Pattern Traces**. System calls record the exact low-level primitives invoked during execution; malicious payloads betray themselves through anomalous surges in process creation primitives (`clone`, `fork`, `execve`), privilege escalation attempts (`chmod`, `setuid`), and socket instantiation. By structuring these system call sequences into contiguous n-grams, Pattern Traces capture sequential behavioral fingerprints (such as opening a sensitive credential file followed immediately by socket creation and data transmission). Because an attacker must interact with the operating system to achieve their malicious objectives, these sequential execution patterns remain unmistakable behavioral signatures that cannot be evaded through code-level obfuscation.

---

## 1. QUT-DV25-Raw 

The **Raw** dataset captures raw execution telemetry collected during `pip install` execution inside an isolated Raspberry Pi sandbox cluster. Data is physically split by ground-truth labels into `QUT-DV25-Benign/` and `QUT-DV25-Malicious/`. Each directory contains the following sub-trace types:

| Directory | Tool | Description |
| :--- | :--- | :--- |
| `QUT-DV25-Opensnoop-Traces/` | `opensnoop-bpfcc` | File opening events recording PID, process name (`COMM`), file descriptor (`FD`), return/error code (`ERR`), and full file system `PATH`. |
| `QUT-DV25-TCP-Traces/` | `tcpstates-bpfcc` | Network telemetry tracking connection state transitions (`OLDSTATE -> NEWSTATE`), local/remote IP addresses, and ports. |
| `QUT-DV25-Filetop-Traces/` | `filetop-bpfcc` | Periodic 5-second sampling of top file I/O operations (`READS`, `WRITES`, `R_Kb`, `W_Kb`, target file path). |
| `QUT-DV25-Pattern-Traces/` | `strace` | Detailed per-thread system call logs (`strace_output_<PID>.<TID>`) capturing every syscall name, arguments, timestamp, and return code. |
| `QUT-DV25-Installation-Traces/`| Terminal stdout/stderr | Raw terminal logs during package installation (dependency resolution, wheel compilation, build errors, or abort traces). |
| `QUT-DV25-PIDs/` | Process tracker | Stores the specific process ID (PID) of the monitored installation process to isolate package behavior from background tasks. |

---

## 2. QUT-DV25-Processed

The **Processed** dataset aggregates, cleans, encodes, and vectorizes the raw traces into tabular `.csv` files. All packages are integrated into single feature tables with a binary ground-truth label:

* `Level = 0`: Benign package

* `Level = 1`: Malicious package

### Feature:
| Category | File | Features |
| :--- | :--- | :---: |
| **Opensnoop Traces** | `QUT-DV25-Opensnoop-Traces.csv` | **12** |
| **TCP Traces** | `QUT-DV25-TCP-Traces.csv` | **8** |
| **Filetop Traces** | `QUT-DV25-Filetop-Traces.csv` | **9** |
| **Install Traces** | `QUT-DV25-Install-Traces.csv` | **6** |
| **SysCall Traces** | `QUT-DV25-SysCall-Traces.csv` | **17** |
| **Pattern Traces** | `QUT-DV25-Pattern-Traces.csv` | **10** |
| **Total** | **6 Categories** | **62 Features** |

#### 1. `QUT-DV25-Opensnoop-Traces.csv`
* **Focus**: File and directory access patterns, detecting unauthorized path traversal and access to sensitive locations.
* **Key Features**:
  * `Package_Name`: Display package name and version
  * `Total_Paths`: Total number of file and directory paths accessed during installation
  * `Total_Error`: Total number of file access errors encountered (e.g., ENOENT, EACCES)
  * `Total_File_Descriptor`: Total number of unique file descriptors allocated
  * `Python_Related_Keywords`: Frequency of Python-specific keywords in accessed paths (e.g., python3, site-packages)
  * `Install_Package_Keywords`: Frequency of installation-related keywords in accessed paths (e.g., pip, setup.py, wheel)
  * `Root_DIR_Installation`: Number of access operations targeting the root directory (e.g., /root, /root/.ssh)
  * `Temporary_DIR_Installation`: Number of access operations targeting temporary directories (e.g., /tmp)
  * `Home_DIR_Installation`: Number of access operations targeting user home directories (e.g., /home/<user>)
  * `User_Access`: Number of access operations targeting system user libraries and binaries (e.g., /usr/lib)
  * `Sys_Access`: Number of access operations targeting system kernel virtual filesystems (e.g., /sys)
  * `Etc_DIR_Installation`: Number of access operations targeting system configuration directories (e.g., /etc)
  * `Other_DIR_Installation`: Number of access operations targeting other system paths (e.g., /proc)
  * `Level`: Ground-truth classification label (0 for benign, 1 for malicious)

#### 2. `QUT-DV25-TCP-Traces.csv`
* **Focus**: Network-level communications, Command-and-Control (C2) callback detection, and suspicious port activity.
* **Key Features**:
  * `Package_Name`: Display package name and version
  * `Total_Entries`: Total number of recorded TCP connection events
  * `Unique_C-COMM`: Number of unique client process/command names initiating network connections
  * `Python_Related_Process`: Number of network events initiated by Python-related processes (e.g., python, pip)
  * `State_Transition`: Distribution and frequency of TCP connection state transitions (e.g., SYN_SENT -> ESTABLISHED)
  * `Local_IP_Address_Access`: Number of unique local IP addresses utilized
  * `Remote_IP_Address_Access`: Number of unique remote IP addresses contacted (external hosts/servers)
  * `Local_Port_Access`: Number of unique local ports opened for outbound connections
  * `Remote_Port_Access`: Number of unique remote destination ports accessed (e.g., 443, 80, 6667)
  * `Level`: Ground-truth classification label (0 for benign, 1 for malicious)

#### 3. `QUT-DV25-Filetop-Traces.csv`
* **Focus**: File I/O transfer volume and read/write process analysis.
* **Key Features**:
  * `Package_Name`: Display package name and version
  * `Total_Reads`: Total count of file read operations performed
  * `Total_Writes`: Total count of file write operations performed
  * `Total_Read_Data_Transfer`: Total volume of data read from files (in KB)
  * `Total_Write_Data_Transfer`: Total volume of data written to files (in KB)
  * `Read_Processes`: List of unique processes performing file read operations
  * `Write_Processes`: List of unique processes performing file write operations
  * `Read_Data_Transfer_Processes`: List of processes responsible for reading file data
  * `Write_Data_Transfer_Processes`: List of processes responsible for writing file data
  * `File_Access_Processes`: Distinct processes accessing files during installation
  * `Level`: Ground-truth classification label (0 for benign, 1 for malicious)

#### 4. `QUT-DV25-Install-Traces.csv`
* **Focus**: Dependency chain tracking, detecting dependency confusion, typosquatting mismatches, and rogue post-install behavior.
* **Key Features**:
  * `Package_Name`: Display package name and version
  * `Total_Dependency_Count`: Total number of dependencies required by the package
  * `Total_Dependencies`: List of all required dependencies (names and versions)
  * `Direct_Dependency_Count`: Number of primary/direct dependencies declared by the package
  * `Direct_Dependencies`: List of direct dependencies declared in metadata or requirements
  * `Indirect_Dependency_Count`: Number of transitive/indirect dependencies resolved during installation
  * `Indirect_Dependencies`: List of resolved transitive dependencies
  * `Level`: Ground-truth classification label (0 for benign, 1 for malicious)

#### 5. `QUT-DV25-SysCall-Traces.csv`
* **Focus**: OS-level operational distribution, identifying system sabotage, persistence, and evasive operations.
* **Key Features**:
  * `Package_Name`: Display package name and version
  * `Total_System_Calls`: Total count of all system calls invoked during installation
  * `Unique_System_Calls`: Number of distinct system call types executed
  * `Unique_System_Calls_List`: Descriptive list of all unique system call names
  * `File_Operations`: Total count of file-related system calls (e.g., openat, newfstatat, unlink, write, read)
  * `Unique_File_Operations`: Count of unique file-related system call types
  * `Unique_File_Operations_List`: Descriptive list of unique file-related system calls
  * `Memory_Operations`: Total count of memory management system calls (e.g., mmap, mprotect, brk, munmap)
  * `Unique_Memory_Operations`: Count of unique memory system call types
  * `Unique_Memory_Operations_List`: Descriptive list of unique memory system calls
  * `Network_Operations`: Total count of network-related system calls (e.g., socket, bind, connect)
  * `Unique_Network_Operations`: Count of unique network system call types
  * `Unique_Network_Operations_List`: Descriptive list of unique network system calls
  * `Process_Management_Operations`: Total count of process management system calls (e.g., clone, fork, execve)
  * `Unique_Process_Management_Operations`: Count of unique process management system call types
  * `Unique_Process_Management_Operations_List`: Descriptive list of unique process management system calls
  * `IO_Operations`: Total count of general I/O system calls (e.g., ioctl, poll)
  * `Unique_IO_Operations`: Count of unique general I/O system call types
  * `Unique_IO_Operations_List`: Descriptive list of unique general I/O system calls
  * `Time_Operations`: Total count of time and timer-related system calls (e.g., clock_gettime, time)
  * `Unique_Time_Operations`: Count of unique time system call types
  * `Unique_Time_Operations_List`: Descriptive list of unique time system calls
  * `IPC_Operations`: Total count of inter-process communication system calls (e.g., pipe, semget)
  * `Unique_IPC_Operations`: Count of unique IPC system call types
  * `Unique_IPC_Operations_List`: Descriptive list of unique IPC system calls
  * `Filesystem_Operations`: Total count of filesystem control system calls (e.g., statfs, mount)
  * `Unique_Filesystem_Operations`: Count of unique filesystem system call types
  * `Unique_Filesystem_Operations_List`: Descriptive list of unique filesystem system calls
  * `Security_Operations`: Total count of security and permission system calls (e.g., getuid, setuid, chmod)
  * `Unique_Security_Operations`: Count of unique security system call types
  * `Unique_Security_Operations_List`: Descriptive list of unique security system calls
  * `Miscellaneous_Operations`: Total count of uncategorized miscellaneous system calls (e.g., uname, getrandom)
  * `Unique_Miscellaneous_Operations`: Count of unique miscellaneous system call types
  * `Unique_Miscellaneous_Operations_List`: Descriptive list of unique miscellaneous system calls
  * `Level`: Ground-truth classification label (0 for benign, 1 for malicious)

* **Note**: The following 11 columns contain raw comma-separated lists of system call names captured during installation. These columns are intended for manual inspection, debugging, and behavioral forensics rather than direct numerical inputs for ML models:

  1. `Unique_System_Calls_List`
  2. `Unique_File_Operations_List`
  3. `Unique_Memory_Operations_List`
  4. `Unique_Network_Operations_List`
  5. `Unique_Process_Management_Operations_List`
  6. `Unique_IO_Operations_List`
  7. `Unique_Time_Operations_List`
  8. `Unique_IPC_Operations_List`
  9. `Unique_Filesystem_Operations_List`
  10. `Unique_Security_Operations_List`
  11. `Unique_Miscellaneous_Operations_List`

#### 6. `QUT-DV25-Pattern-Traces.csv`
* **Focus**: Sequential behavioral patterns represented via n-grams over system call traces.
* **Key Features**:
  * `Package_Name`: Display package name and version
  * `Pattern_1`: Sequential system call n-gram for file metadata inspection (e.g., newfstatat -> openat -> fstat)
  * `Pattern_2`: Sequential system call n-gram for file reading operations (e.g., read -> pread64 -> lseek)
  * `Pattern_3`: Sequential system call n-gram for file writing operations (e.g., write -> pwrite64 -> fsync)
  * `Pattern_4`: Sequential system call n-gram for network socket creation (e.g., socket -> bind -> listen)
  * `Pattern_5`: Sequential system call n-gram for process creation and execution (e.g., fork -> execve -> wait4)
  * `Pattern_6`: Sequential system call n-gram for memory allocation and deallocation (e.g., mmap -> mprotect -> munmap)
  * `Pattern_7`: Sequential system call n-gram for file descriptor management (e.g., dup -> dup2 -> close)
  * `Pattern_8`: Sequential system call n-gram for inter-process communication piping (e.g., pipe -> write -> read)
  * `Pattern_9`: Sequential system call n-gram for file locking operations (e.g., fcntl -> lockf -> close)
  * `Pattern_10`: Sequential system call n-gram for error handling patterns (e.g., open -> read -> error=ENOENT)
  * `Level`: Ground-truth classification label (0 for benign, 1 for malicious)

---

## Selected Features - SEF

From the initial set of **62 Candidate Features**, 22 highly correlated features ($|r| > 0.50$) were removed via Pearson Correlation Analysis to eliminate multicollinearity, yielding 40 Independent Features (IDF). The remaining features were evaluated using Importance Scores (IMS) across machine learning models (Random Forest, Decision Tree, SVM, Gradient Boosting), ultimately retaining **36 Selected Engineered Features (SEF)** that met the high-importance threshold ($IMS > 0.08$):

| # | Category | Feature Name | Description |
| :-: | :--- | :--- | :--- |
| 1 | **OpensnoopTraces** | `Root_DIR_Installation` | Access operations targeting the root administrative directory (e.g., `/root`, `/root/.ssh`) |
| 2 | **OpensnoopTraces** | `Temporary_DIR_Installation` | Access operations targeting temporary staging directories (e.g., `/tmp`) |
| 3 | **OpensnoopTraces** | `Home_DIR_Installation` | Access operations targeting user personal directories (e.g., `/home/<user>`) |
| 4 | **OpensnoopTraces** | `User_Access` | Access operations targeting user system binaries and shared libraries (e.g., `/usr/lib`) |
| 5 | **OpensnoopTraces** | `Sys_Access` | Access operations targeting the kernel virtual filesystem (e.g., `/sys`) |
| 6 | **OpensnoopTraces** | `Etc_DIR_Installation` | Access operations targeting system configuration files (e.g., `/etc`, `/etc/hosts`) |
| 7 | **OpensnoopTraces** | `Other_DIR_Installation` | Operations involving other special system directories (e.g., `/proc`) |
| 8 | **TCPTraces** | `State_Transition` | Distribution and frequency of TCP connection lifecycle state changes |
| 9 | **TCPTraces** | `Local_IP_Address_Access` | Number of distinct local IP addresses utilized during installation |
| 10 | **TCPTraces** | `Remote_IP_Address_Access` | Number of unique external/remote IP addresses contacted |
| 11 | **TCPTraces** | `Local_Port_Access` | Number of distinct local outbound ports opened |
| 12 | **TCPTraces** | `Remote_Port_Access` | Number of distinct remote destination ports accessed (e.g., 443, 80, 6667) |
| 13 | **FiletopTraces** | `Read_Processes` | Distinct processes executing file read operations |
| 14 | **FiletopTraces** | `Write_Processes` | Distinct processes executing file write operations |
| 15 | **FiletopTraces** | `Read_Data_Transfer_Processes` | Processes responsible for reading data transfer volume |
| 16 | **FiletopTraces** | `Write_Data_Transfer_Processes` | Processes responsible for writing data transfer volume |
| 17 | **FiletopTraces** | `File_Access_Processes` | Specific processes accessing critical files during installation |
| 18 | **InstallTraces** | `Total_Dependencies` | List and names of all required dependencies |
| 19 | **InstallTraces** | `Direct_Dependencies` | List of primary direct dependencies declared by the package |
| 20 | **InstallTraces** | `Indirect_Dependencies` | List of transitive/indirect dependencies resolved during installation |
| 21 | **SysCallTraces** | `File_Operations` | Total count of file-related system calls (`openat`, `newfstatat`, `unlink`, `chmod`) |
| 22 | **SysCallTraces** | `Network_Operations` | Total count of network-related system calls (`socket`, `connect`, `bind`, `listen`) |
| 23 | **SysCallTraces** | `Process_Management_Operations` | Total count of process management system calls (`fork`, `clone`, `execve`, `exit_group`) |
| 24 | **SysCallTraces** | `IO_Operations` | Total count of general input/output system calls (`ioctl`, `poll`, `readv`, `writev`) |
| 25 | **SysCallTraces** | `Time_Operations` | Total count of timer and time-related system calls (`clock_gettime`, `time`, `alarm`) |
| 26 | **SysCallTraces** | `Security_Operations` | Total count of security and permission system calls (`getuid`, `setuid`, `chmod`) |
| 27 | **PatternTraces** | `Pattern_1` | System call n-gram for file metadata inspection (`newfstatat -> openat -> fstat`) |
| 28 | **PatternTraces** | `Pattern_2` | System call n-gram for sequential file reading (`read -> pread64 -> lseek`) |
| 29 | **PatternTraces** | `Pattern_3` | System call n-gram for file writing and synchronization (`write -> pwrite64 -> fsync`) |
| 30 | **PatternTraces** | `Pattern_4` | System call n-gram for outbound network socket creation (`socket -> bind -> listen`) |
| 31 | **PatternTraces** | `Pattern_5` | System call n-gram for process creation and execution (`fork -> execve -> wait4`) |
| 32 | **PatternTraces** | `Pattern_6` | System call n-gram for memory allocation and deallocation (`mmap -> mprotect -> munmap`) |
| 33 | **PatternTraces** | `Pattern_7` | System call n-gram for file descriptor management (`dup -> dup2 -> close`) |
| 34 | **PatternTraces** | `Pattern_8` | System call n-gram for inter-process communication piping (`pipe -> write -> read`) |
| 35 | **PatternTraces** | `Pattern_9` | System call n-gram for file locking mechanisms (`fcntl -> lockf -> close`) |
| 36 | **PatternTraces** | `Pattern_10` | System call n-gram for exception and error handling patterns (`open -> read -> error=ENOENT`) |

---

## Why choose

The selection of these 36 features was driven by a two-stage feature engineering pipeline designed to eliminate redundant signals, resolve multicollinearity, and maximize the classification power of machine learning models. From an initial pool of 62 Candidate Features (CF), 22 dependent features exhibited high pairwise correlation ($|r| > 0.50$) via Pearson Correlation Analysis. Retaining strongly correlated features causes multicollinearity, which inflates model variance and skews tree-based algorithms like Random Forest. For instance, in FiletopTraces, raw volume metrics like `Total_Reads` and `Total_Read_Data_Transfer` strongly overlapped with process activity lists, while in InstallTraces, integer dependency counters were directly collinear with the actual dependency sets. Eliminating these redundant metrics produced a streamlined set of 40 Independent Features (IDF) without losing critical behavioral information.

To refine the feature space further, an Importance Score (IMS) metric was evaluated across four diverse machine learning models: Random Forest (RF), Decision Tree (DT), Support Vector Machine (SVM), and Gradient Boosting (GB). Features were filtered according to their cross-model importance, retaining only the 36 Selected Engineered Features (SEF) that satisfied the stringent importance threshold of $IMS > 0.08$. This achieved a 58% reduction in feature dimensionality, significantly accelerating inference speed down to approximately 0.41 seconds per package while simultaneously improving detection accuracy, precision, and recall by preventing model overfitting.

From a cybersecurity perspective, these 36 features represent the most discriminative behavioral indicators of malicious Python packages. The 7 selected Opensnoop features isolate unauthorized reconnaissance into sensitive directories (such as `/root/.ssh` and `/etc`) rather than relying on noisy generic path counts. The 5 TCP features capture anomalous destination ports and connection lifecycles that unmask Command-and-Control communication. The 5 Filetop features pinpoint rogue processes (like `bash` or `curl`) spawning during installation, while the 3 Install features uncover dependency confusion attacks. Meanwhile, the 6 core SysCall categories capture fundamental low-level OS operations like process spawning and permission alterations. 

Most importantly, all 10 Pattern features were retained because they demonstrated virtually no inter-feature correlation ($|r| \le 0.49$) and achieved the highest individual importance scores across all classifiers. Because sequential n-grams capture the chronological logic of multi-stage attacks—such as inspecting file metadata, allocating memory, opening a network socket, and piping data—they provide robust, invariant behavioral signatures that adversaries cannot circumvent through traditional code obfuscation or variable renaming.