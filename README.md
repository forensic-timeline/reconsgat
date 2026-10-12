# reconsgat

## What is SGAT?

**SGAT (Semantic Graph with Attacker Tracking)** is an attacker-centric forensic event reconstruction tool for web attacks. Given the logs collected from a compromised web server, SGAT reconstructs the sequence of attack activities and attributes each activity to the attacker responsible for it. This allows an investigator to review the full incident or focus on a specific attacker.

### How it works

SGAT processes server-side logs (`access.log`, `error.log`, `auth.log`, `syslog`) through three main stages:

1. **Normalization**: encoded payloads are decoded to reveal hidden commands and conduct actor extraction form log timeline.
2. **Anomaly detection**: each log entry in the timeline is matched against [Sigma rules](https://github.com/SigmaHQ/sigma) to detect suspicious activity and assign a semantic label.
3. **Semantic graph reconstruction**: events are mapped into a graph ([Neo4j](https://neo4j.com/)), where SGAT identifies attackers, tracks their activities, and aggregates related events into high-level events, each attributed to its attacker and mapped to [MITRE ATT&CK](https://attack.mitre.org/) techniques and tactics.

The result is a four-layer reconstruction (low-level events, high-level events (**the reconstruction results**), techniques, tactics).

## Requirements

SGAT is implemented in Python, so a working Python environment is required. Please follow the [official documentation](https://www.python.org/downloads/) to download and install Python (version 3.X or later).

SGAT uses a graph database to store the reconstructed graph, perform attacker identification and tracking, and visualize the results. SGAT is built on [Neo4j](https://neo4j.com/), please follow the [installation guide](https://neo4j.com/docs/operations-manual/current/installation/) to set it up. Once installed, Neo4j can be accessed locally, and a database must be created beforehand following this [documentation](https://neo4j.com/docs/operations-manual/current/manage-databases/).

Anomaly detection relies on [Sigma rules](https://github.com/SigmaHQ/sigma) and a set of web-forensic detection rules. The required rule sets are included in this repository (or can be downloaded from their respective sources).

The forensic timeline is generated using [Plaso (log2timeline)](https://github.com/log2timeline/plaso), which aggregates the raw logs into a single chronological timeline. Please follow the [installation documentation](https://plaso.readthedocs.io/en/latest/sources/user/Installing.html) to install it.

Finally, the Python dependencies can be installed via:

```bash
pip install -r requirements.txt
```

## Prerequisites

- Python 3.13 or higher
- Git
- Python virtual environment (venv or conda)

## Python Virtual Environment Setup

1. Anaconda or Miniconda

    ```bash
    conda create --name reconsgat python=3.13
    conda activate reconsgat
    ```
Or:

2. Venv

    ```bash
    python -m venv venv
    source venv/bin/activate
      ```

## Installation

1. **Clone the Repository**
2. **Install Depedencies**

    ```bash
    cd reconsgat
    pip install -r requirements.txt
    ```

## Running the Application

To run SGAT reconstruction:

```bash
python reconstruction.py sample
```

To evaluate the result:

```bash
python evaluation.py sample
```

**sample** is the name of the dataset, make sure database called **sample** is also exist in Neo4j.