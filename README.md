# FireCracker: A Firebase Misconfiguration Scanner

## Overview

**FireCracker** is an open-source tool designed to enhance the security of Firebase databases. It scans APK files for Firebase URLs and checks these instances for common misconfigurations. If there's a misconfiguration, FireCracker will attempt to exploit it by writing data. This process helps developers and security analysts identify and rectify potential vulnerabilities in their Firebase setups. FireCracker's mission is to promote better security practices and awareness within the development community, making it harder for attackers to exploit misconfigured databases.

## Features

- **APK Scanning**: Analyze single APK files or directories containing multiple APK files to extract Firebase URLs.
- **Misconfiguration Detection**: Identify Firebase databases that may be vulnerable due to misconfigurations, such as unauthenticated read/write access.
- **Automated Exploiting**: Attempt to exploit identified vulnerabilities to demonstrate potential security issues.
- **User-Friendly**: Designed with usability in mind, FireCracker can be utilized by both developers and security professionals, regardless of their expertise in security.

## Why FireCracker?

Firebase is a widely used backend platform for mobile and web applications. However, its convenience sometimes leads to overlooked security configurations, exposing sensitive data. FireCracker addresses this issue by:

- Providing a straightforward method for identifying potential security risks.
- Offering a platform for educational purposes to emphasize the importance of secure Firebase configurations.
- Serving as a tool for security audits and compliance checks.

## Quick Start

1. **Clone the Repository**: `git clone https://github.com/0xalmighty/FireCracker.git`
2. **Install Dependencies**: Follow the installation guide in docs.
3. **Run FireCracker**: Use the command-line interface to scan APK files or directories for Firebase misconfigurations.
4. **Review Results**: Analyze the output and take the necessary actions to secure your Firebase instances.

## Usage

### Description

FireCracker simplifies the detection of security vulnerabilities in Firebase databases by scanning APK files for Firebase URLs.

### Requirements

- Go 1.22.0 or later
- apktool

### Installation

1. Clone the repository
```bash
git clone https://github.com/0xAlmighty/FireCracker.git
```
2. Change to the git directory
```bash
cd FireCracker
```
3. Build
```bash
go build
```
*Optionally, add to **PATH** for easier access*

## Basic Usage
```bash
FireCracker -input <input_file>
```

### Options
- ```-input```:  Use for individual APK files 
- ```-folder```: for directories with lots of APK files.

## Example
Assuming you have a directory named ```APKs``` containing various APK files, you can scan all these files for Firebase misconfigurations using FireCracker:

Navigate to the FireCracker directory
```bash
cd path/to/FireCracker
```
Scan a directory of APK files
```bash
./firecracker -folder /path/to/APKs
```
For scanning a single APK file
```bash
./firecracker -input /path/to/single.apk
```

## Output
FireCracker outputs a list of Firebase URLs found within the APKs, indicating whether each URL is secure, vulnerable, or misconfigured based on the detected access permissions and settings.

## Contributing
We welcome contributions from the community! Whether you're interested in fixing bugs, adding new features, or improving documentation, there's space for you. Check out our [Contributing Guide](https://github.com/0xAlmighty/FireCracker/blob/main/CONTRIBUTING.md) for more details on how to get started.

## License
FireCracker is released under the MIT License. See the [LICENSE](https://github.com/0xAlmighty/FireCracker/blob/main/LICENSE.md) file for more details.

## Support
Need help? Have suggestions? Feel free to reach out :) almightysec @ pm.me
