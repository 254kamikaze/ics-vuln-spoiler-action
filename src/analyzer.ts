import Anthropic from "@anthropic-ai/sdk";
import type { CommitInfo, VulnerabilityAnalysis } from "./types.js";

let client: Anthropic;
let modelId: string;

export function initAnalyzer(apiKey: string, model: string): void {
  client = new Anthropic({ apiKey });
  modelId = model;
}

const ANALYSIS_PROMPT = `You are an ICS/OT security researcher analyzing git commits to industrial control system software to identify security vulnerability patches.

Analyze the following commit and determine if it is patching an EXPLOITABLE security vulnerability in OT/ICS software.

## Commit Information
**SHA:** {sha}
**Author:** {author}
**Date:** {date}
**Message:**
{message}
{prSection}
## Diff
{diff}

## Industrial Protocol Knowledge

You must understand these industrial protocols to assess vulnerability impact:

### Modbus (TCP/RTU)
- Function codes: 0x01 Read Coils, 0x02 Read Discrete Inputs, 0x03 Read Holding Registers, 0x04 Read Input Registers, 0x05 Write Single Coil, 0x06 Write Single Register, 0x0F Write Multiple Coils, 0x10 Write Multiple Registers
- No built-in authentication -- any network access = full read/write
- Transaction ID, Protocol ID, Unit ID, Function Code, Data structure
- Attacks target register overwrites to manipulate physical outputs

### OPC UA (OPC Unified Architecture)
- Services: Browse, Read, Write, Call (method invocation), CreateSubscription, Publish, CreateMonitoredItems
- Security modes: None, Sign, SignAndEncrypt
- Authentication: Anonymous, Username/Password, X509 Certificate
- Session management, secure channel establishment
- Node addressing via NodeId (namespace + identifier)
- Attacks target auth downgrade (forcing SecurityMode=None), session hijacking, malicious method calls

### S7 (Siemens S7comm / S7comm-plus)
- PDU types: Job (request), Ack_Data (response), UserData
- Memory areas: DB (data blocks), inputs (I), outputs (Q), merkers (M), counters (C), timers (T)
- Functions: Read/Write variables, Download/Upload blocks, PLC Start/Stop/Reset
- S7comm-plus adds integrity protection (anti-replay)
- Attacks target unauthorized PLC stop/start, DB memory writes, block uploads

### BACnet (Building Automation)
- Services: ReadProperty, WriteProperty, ReadPropertyMultiple, WritePropertyMultiple, ReinitializeDevice, DeviceCommunicationControl, ConfirmedCOVNotification
- Object types: AnalogInput, AnalogOutput, BinaryInput, BinaryOutput, Device, Schedule
- Attacks target WriteProperty to setpoints, ReinitializeDevice for reboot, DeviceCommunicationControl to isolate devices

### EtherNet/IP (CIP - Common Industrial Protocol)
- Services: Get_Attribute_Single/All, Set_Attribute_Single/All, Forward_Open, Forward_Close
- Objects: Identity, MessageRouter, Assembly, Connection Manager
- Attacks target assembly object writes for I/O manipulation, unauthorized Forward_Open for implicit messaging

### MQTT (Message Queuing Telemetry Transport)
- Operations: CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PINGREQ
- QoS levels: 0 (at most once), 1 (at least once), 2 (exactly once)
- Topic hierarchy with wildcards: + (single level), # (multi level)
- Attacks target topic injection (subscribing to # for full data exfiltration), malicious PUBLISH to control topics, auth bypass

### DNP3 (Distributed Network Protocol)
- Objects: Binary Input, Binary Output, Analog Input, Analog Output, Counter, Class Data
- Functions: Read, Write, Direct Operate, Select Before Operate (SBO), Cold/Warm Restart, Enable/Disable Unsolicited
- Secure Authentication (SA) v5 with challenge-response
- Attacks target Direct Operate bypassing SBO safety, unsolicited response spoofing, SA bypass

## OT Attack Pattern Categories

Classify the vulnerability into exactly one of these categories:
- \`protocol-parsing\` -- Buffer overflows, format string bugs, or memory corruption in protocol message parsing (PDU deserialization, frame handling)
- \`plc-logic-injection\` -- Unauthorized writes to PLC memory (registers, coils, data blocks) that alter control logic or setpoints
- \`auth-bypass\` -- Authentication or authorization bypass in HMI, SCADA, engineering workstation, or protocol session establishment
- \`command-injection\` -- OS command injection via SCADA web interfaces, engineering tools, or protocol gateways
- \`insecure-defaults\` -- Unsafe default configurations: open ports, default credentials, disabled security features, permissive ACLs
- \`input-validation\` -- Missing or insufficient validation on protocol fields, configuration parameters, or user input that enables exploitation
- \`sis-bypass\` -- Bypassing Safety Instrumented Systems: disabling safety interlocks, overriding trip points, manipulating safety controllers
- \`info-disclosure\` -- Leaking process variables, credentials, PLC programs, network topology, or firmware through protocol responses or error messages
- \`dos-control-system\` -- Denial of service against control systems: crashing PLCs/RTUs, exhausting protocol resources, disrupting real-time communication
- \`insecure-update\` -- Firmware, logic, or configuration updates without integrity verification: unsigned uploads, unverified block transfers

## OT Severity Model (Impact-Based)

Severity is based on OT-specific impact, NOT standard IT severity:
- **Critical** = Safety/physical impact: could cause equipment damage, environmental release, or human safety risk. Examples: overwriting safety PLC registers, bypassing SIS interlocks, disabling emergency shutdown, manipulating physical actuators beyond safe limits
- **High** = Process disruption: could halt or manipulate industrial processes without direct safety impact. Examples: unauthorized PLC stop/start, register writes that change setpoints, SCADA session hijack to alter process view
- **Medium** = Information disclosure: leaking process data, credentials, topology, or PLC programs. Examples: reading all Modbus registers without auth, extracting PLC block code, credential leakage from HMI
- **Low** = Availability impact: denial of service, degraded performance, resource exhaustion. Examples: crashing a protocol parser with malformed packets, MQTT broker resource exhaustion, connection table overflow

## Instructions

Your task is to identify commits that patch REAL, EXPLOITABLE security vulnerabilities in ICS/OT software. You must demonstrate the vulnerability with a concrete, protocol-specific proof of concept.

Only flag a commit as a vulnerability patch if ALL of the following are true:
1. The code BEFORE the patch had a clear security flaw relevant to industrial control systems
2. You can write a specific proof of concept showing how to exploit it using industrial protocol payloads or OT-specific attack vectors
3. The vulnerability has real OT security impact (process safety, process integrity, or availability)

DO NOT flag:
- General code quality improvements or defensive coding practices
- Adding validation that prevents edge cases but has no security impact
- Performance fixes or refactoring
- Error handling improvements without security implications
- Changes that only affect internal/trusted code paths
- Test-only changes or documentation updates
- Commits where you cannot write a concrete exploit PoC with protocol-specific payloads

Respond with a JSON object (and nothing else) in the following format:
{
  "isVulnerabilityPatch": boolean,
  "vulnerabilityType": string | null,
  "severity": "Critical" | "High" | "Medium" | "Low" | null,
  "description": string | null,
  "affectedCode": string | null,
  "proofOfConcept": string | null,
  "otCategory": "protocol-parsing" | "plc-logic-injection" | "auth-bypass" | "command-injection" | "insecure-defaults" | "input-validation" | "sis-bypass" | "info-disclosure" | "dos-control-system" | "insecure-update" | null,
  "affectedProtocol": string | null,
  "purdueLayer": "L0" | "L1" | "L2" | "L3" | "L4" | "L5" | null,
  "safetyImpact": string | null
}

If this is NOT an exploitable OT security vulnerability patch, set isVulnerabilityPatch to false and all other fields to null.

If this IS patching an exploitable OT vulnerability:
- vulnerabilityType: The vulnerability class (e.g., "Buffer Overflow in Modbus PDU Parsing", "OPC UA Authentication Bypass", "PLC Register Write Without Authorization")
- severity: Based on the OT severity model above (Critical/High/Medium/Low)
- description: 2-3 sentences explaining the vulnerability, the industrial impact, and how the patch fixes it
- affectedCode: The vulnerable code snippet BEFORE the patch (max 5 lines)
- proofOfConcept: A CONCRETE exploit example with protocol-specific payloads (see examples below)
- otCategory: One of the 10 OT attack pattern categories listed above
- affectedProtocol: The affected industrial protocol (e.g., "Modbus TCP", "OPC UA", "S7comm", "BACnet", "EtherNet/IP", "MQTT", "DNP3")
- purdueLayer: The Purdue model layer where this vulnerability exists (L0=physical process, L1=basic control, L2=area supervision, L3=site operations, L4=enterprise, L5=DMZ)
- safetyImpact: If severity is Critical, describe the specific physical/safety consequence. Otherwise null.

## Protocol-Specific PoC Examples

Your proofOfConcept MUST use protocol-specific payloads like these:

### Modbus register write (manipulate process setpoint):
\`\`\`python
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('192.168.1.10', port=502)
# Write holding register 40001 (reactor temperature setpoint) to unsafe value
client.write_register(0, 9999, unit=1)  # Overwrite setpoint to 9999 degrees
\`\`\`

### OPC UA authentication downgrade:
\`\`\`python
from opcua import Client
client = Client("opc.tcp://192.168.1.20:4840")
client.set_security_string("None,None,None")  # Force no security
client.connect()
# Browse and write to safety-critical nodes without authentication
node = client.get_node("ns=2;s=ReactorPressure.Setpoint")
node.set_value(999.9)
\`\`\`

### S7 data block write (alter PLC logic):
\`\`\`python
import snap7
client = snap7.client.Client()
client.connect('192.168.1.30', 0, 1)
# Write to DB1 offset 0, overwriting safety interlock flag
data = bytearray([0x00])  # Disable safety interlock
client.db_write(1, 0, data)
\`\`\`

### BACnet device reset:
\`\`\`python
import BAC0
bacnet = BAC0.connect()
# ReinitializeDevice to force controller reboot
bacnet.send_reinit_request('192.168.1.40', state='coldstart')
\`\`\`

### MQTT topic injection (subscribe to all control topics):
\`\`\`python
import paho.mqtt.client as mqtt
client = mqtt.Client()
client.connect("192.168.1.50", 1883)
# Subscribe to all topics including control channels
client.subscribe("#")  # Wildcard captures all SCADA telemetry
# Publish malicious setpoint to control topic
client.publish("plant/reactor/temperature/setpoint", "9999")
\`\`\`

If you cannot write a specific, concrete proof of concept with protocol-level payloads, set isVulnerabilityPatch to false.`;

export async function analyzeCommit(
  commit: CommitInfo
): Promise<VulnerabilityAnalysis> {
  let prSection = "";
  if (commit.pullRequest) {
    const pr = commit.pullRequest;
    prSection = `
## Associated Pull Request
**PR #${pr.number}:** ${pr.title}
**URL:** ${pr.url}
**Labels:** ${pr.labels.length > 0 ? pr.labels.join(", ") : "None"}
${pr.body ? `**Description:**\n${pr.body.substring(0, 1000)}${pr.body.length > 1000 ? "..." : ""}` : ""}
`;
  }

  const replacements: Record<string, string> = {
    "{sha}": commit.sha,
    "{author}": commit.author,
    "{date}": commit.date,
    "{message}": commit.message,
    "{prSection}": prSection,
    "{diff}": commit.diff,
  };

  const prompt = ANALYSIS_PROMPT.replace(
    /\{sha\}|\{author\}|\{date\}|\{message\}|\{prSection\}|\{diff\}/g,
    (match) => replacements[match] ?? match
  );

  const response = await client.messages.create({
    model: modelId,
    max_tokens: 2048,
    messages: [
      { role: "user", content: prompt },
      { role: "assistant", content: "{" },
    ],
  });

  const content = response.content[0];
  if (content.type !== "text") {
    throw new Error("Unexpected response type from Claude API");
  }

  try {
    const analysis = JSON.parse("{" + content.text) as VulnerabilityAnalysis;
    return analysis;
  } catch {
    return {
      isVulnerabilityPatch: false,
      vulnerabilityType: null,
      severity: null,
      description: null,
      affectedCode: null,
      proofOfConcept: null,
      otCategory: null,
      affectedProtocol: null,
      purdueLayer: null,
      safetyImpact: null,
    };
  }
}
