# Burp Suite (Community Edition) cheat sheet for web application testing

This Burp Suite Community Edition cheat sheet provides comprehensive guidance for manual web application security testing, leveraging the tool's powerful features while working within the limitations of the free version.

### Installation & Setup

Installing Burp Suite Community Edition and initial configuration for web testing.

bash

```
# Download from PortSwigger website
# https://portswigger.net/burp/communitydownload

# Install on Kali Linux (pre-installed)
sudo apt update && sudo apt install burpsuite

# Launch Burp Suite
burpsuite &

# Java requirement (Burp is Java-based)
java -version

# Command line launch with specific options
java -jar burpsuite_community.jar

# Increase memory allocation for large projects
java -Xmx4G -jar burpsuite_community.jar

# Set up browser proxy configuration
# Firefox: Preferences → Network Settings → Manual proxy
# HTTP Proxy: 127.0.0.1 Port: 8080
# Also proxy SSL: 127.0.0.1 Port: 8080

# Install CA certificate for HTTPS interception
# Visit http://burp in browser → Click "CA Certificate"
# Import certificate into browser trust store
```

### Project Configuration & Workspace Setup

Creating projects, configuring scope, and setting up the testing environment.

bash

```
# Create new project
# Temporary project (Community Edition limitation)
# Or save to file (requires manual saving)

# Configure target scope
# Target tab → Scope → Add from scope
https://target.com
https://*.target.com

# Set up exclude rules
# Target → Scope → Exclude from scope
.*\.googleapis\.com
.*\.cloudfront\.net

# Configure session handling
# Project options → Sessions → Session Handling Rules
# Add rule for authentication maintenance

# Set up project-level options
# Project options → Connections → Platform authentication
# Project options → HTTP → Redirections: Always follow
```

### Proxy & Interception Phase

Intercepting and analyzing HTTP/S traffic between browser and target.

bash

```
# Start interception
Proxy → Intercept → Turn Intercept on/off (Ctrl+I)

# Configure interception scope
Proxy → Options → Intercept Client Requests
# Add URL-based filters: ^.*target\.com.*$

# Set up response interception
Proxy → Options → Intercept Server Responses
# Enable for specific status codes: 4xx, 5xx

# Configure proxy listeners
Proxy → Options → Proxy Listeners
# Add listener on 127.0.0.1:8080
# Bind to specific interface if needed

# Use invisible proxy mode
Proxy → Options → Proxy Listeners → Edit → Support invisible proxying

# Export intercepted traffic
Proxy → HTTP history → Select items → Right click → Save items

# Filter history by various parameters
# Filter by: Method, Status, MIME type, Search term, etc.
```

### Spidering & Content Discovery

Automatically discovering application content and functionality.

bash

```
# Start spidering from target scope
Target → Site map → Right click domain → Spider this host

# Configure spider options
Spider → Options
# Set check robots.txt, detect custom 404, etc.

# Control spider scope
Spider → Options → Spider Scope
# Use custom scope: Only URLs matching patterns

# Passive spidering (while browsing)
# Burp automatically builds site map from proxy traffic

# Use content discovery (brute force directories)
Target → Site map → Right click → Engagement tools → Discover content

# Configure content discovery wordlists
# Use built-in short wordlist or custom lists
# Set file extensions: .php, .html, .jsp, .asp, etc.
```

### Manual Testing with Repeater

Manually manipulating and reissuing requests for targeted testing.

bash

```
# Send request to Repeater
Proxy → HTTP history → Right click → Send to Repeater (Ctrl+R)

# Modify request parameters
# Change method: GET → POST
# Modify headers, cookies, parameters
# Encode/decode data (Ctrl+Shift+E)

# Use multiple Repeater tabs
# Right click request → Send to new Repeater tab

# Compare requests/responses
Repeater → Right click → Show response in browser
# Or use "Compare" feature

# Automated testing with Repeater
# Use Macros (Project options → Sessions) for authentication replay
# Use Extensions for automated parameter testing

# Save Repeater requests
Repeater → Right click → Save item
```

### Automated Scanning (Limited in Community)

Using Burp's limited automated scanning capabilities in Community Edition.

bash

```
# Manual audit issues (passive scanning)
# Burp automatically flags issues in proxy history

# Initiate active scan (limited functionality)
Target → Site map → Right click → Actively scan this host

# Configure scan options
Scanner → Options → Active Scanning Optimization
# Set to Thorough for maximum coverage

# Review scan results
Dashboard → Issue activity
# Filter by severity: High, Medium, Low, Information

# Export scan reports
Dashboard → Issue activity → Select issues → Report issues
# Formats: HTML, XML

# Use live passive scanning
Scanner → Live Passive Scanning → Enable
```

### Intruder for Fuzzing & Brute Force

Automated attack tool for parameter fuzzing, enumeration, and brute force.

bash

```
# Send request to Intruder
Proxy → HTTP history → Right click → Send to Intruder (Ctrl+I)

# Configure attack positions
Intruder → Positions → Clear §
# Mark parameters with §parameter§

# Choose attack type:
# Sniper: Single payload set, one position at a time
# Battering ram: Single payload set, all positions same
# Pitchfork: Multiple payload sets, parallel positions
# Cluster bomb: Multiple payload sets, all combinations

# Configure payloads
Intruder → Payloads
# Simple list, runtime file, numbers, dates, custom iterator

# Set up payload processing
Intruder → Payloads → Payload processing
# Add: URL encode, base64 encode, substring, etc.

# Configure attack options
Intruder → Options
# Set request engine, grep match, error detection

# Start attack
Intruder → Start attack

# Analyze results
# Sort by status, length, grep matches
# Save results to file
```

### Sequencer for Session Token Analysis

Analyzing randomness and predictability of session tokens.

bash

```
# Capture login response with session token
# Send to Sequencer: Right click → Send to Sequencer

# Configure token location
Sequencer → Select Live Capture
# Choose: Cookie, form field, custom location

# Configure live capture options
Sequencer → Configure live capture
# Set token location, number of requests

# Start live capture
Sequencer → Start live capture

# Analyze results
# Check: Effective entropy, character-level analysis
# Review: Reliability of results

# Manual load option
# Use previously captured tokens from file
```

### Decoder & Comparer Utilities

Encoding/decoding data and comparing request/response differences.

bash

```
# Use Decoder for data transformation
# Send data to Decoder: Right click → Send to Decoder

# Common encoding/decoding operations:
# URL encode/decode
# Base64 encode/decode
# HTML encode/decode
# Hex conversion
# Hash generation: MD5, SHA1, SHA256

# Smart decode feature
# Automatically detects encoding

# Use Comparer for differential analysis
# Send two items to Comparer: Right click → Send to Comparer

# Compare types:
# Words (by words)
# Bytes (hex view)

# Analyze differences
# Synchronized scrolling between compared items
```

### Extender for Custom Functionality

Extending Burp functionality with BApps and custom extensions.

bash

```
# Access BApp store
Extender → BApp store
# Browse and install community extensions

# Install common BApps:
# Logger++ - Enhanced logging
# Autorize - Authorization testing
# Turbo Intruder - High-speed fuzzing
# CSRF Scanner - CSRF vulnerability detection

# Load custom extensions
Extender → Extensions → Add
# Support for: Java, Python (Jython), Ruby (JRuby)

# Configure extension options
Extender → Options
# Set Python/Ruby environment locations

# Monitor extension output
Extender → Extensions → Select extension → Output
```

### Manual Testing Techniques

Step-by-step manual testing approaches for common vulnerabilities.

bash

```
# SQL Injection testing:
# 1. Find input parameters in Repeater
# 2. Test with: ' OR '1'='1
# 3. Test with: ' UNION SELECT 1,2,3--
# 4. Use Intruder for blind SQLi timing attacks

# XSS testing:
# 1. Test with: <script>alert(1)</script>
# 2. Test event handlers: onmouseover=alert(1)
# 3. Test in different contexts: HTML, attribute, JavaScript

# CSRF testing:
# 1. Check for anti-CSRF tokens
# 2. Test token removal/duplication
# 3. Use CSRF PoC generator in Engagement tools

# Authentication testing:
# 1. Test credential brute force with Intruder
# 2. Check session management issues
# 3. Test privilege escalation

# File upload testing:
# 1. Upload different file types
# 2. Bypass extension filters
# 3. Test for path traversal in file names
```

### Workflow Optimization Tips

Optimizing the testing workflow within Community Edition limitations.

bash

```
# Use project files (manual save required)
# Save project frequently: Ctrl+S

# Configure browser properly
# Disable browser cache for testing
# Use Burp's built-in browser (if available) or configured browser

# Set up efficient workspace layout
# Save window layout: Window → Save layout

# Use search functionality extensively
# Search: Ctrl+F across all tools

# Configure target scope carefully
# Use include and exclude rules effectively

# Leverage engagement tools
# Target → Site map → Engagement tools
# Find comments, scripts, forms

# Use collaborator for out-of-band testing
# Burp → Burp Collaborator client
# Generate payloads and monitor for callbacks
```

### Common Keyboard Shortcuts

bash

```
Ctrl+I - Toggle interception
Ctrl+R - Send to Repeater
Ctrl+Shift+I - Send to Intruder
Ctrl+B - Send to Scanner
Ctrl+U - Send to Decoder
Ctrl+Shift+B - Send to Comparer
Ctrl+F - Search
Ctrl+S - Save project
Space - Forward intercepted request
Ctrl+Shift+E - Encode/decode selected text
```

### Useful Extensions for Community Edition

bash

```
# Essential BApps for manual testing:
- Logger++ - Enhanced logging and analysis
- Autorize - Automatic authorization testing
- Turbo Intruder - High-speed payload processing
- Request Timer - Timing analysis for race conditions
- Additional Scanner Checks - Extended passive checks
- J2EEScan - J2EE-specific vulnerability detection
- Backslash Powered Scanner - Additional scan checks
- ActiveScan++ - Extended active scan checks
- Param Miner - Hidden parameter discovery
- Content Type Converter - Content type manipulation
```

### Reporting & Documentation

Generating reports and documenting findings in Community Edition.

bash

```
# Export issues report
Dashboard → Issue activity → Select issues → Report issues
# Choose format: HTML, XML

# Copy requests/responses
# Right click → Copy URL, Copy as curl command
# Copy response headers/body

# Save site map
Target → Site map → Right click → Save selected items

# Generate proof of concept
# Right click issue → Generate PoC

# Document manually (Community Edition limitation)
# Use screenshots, saved requests, and manual notes
# Combine with other tools for comprehensive reporting
```

