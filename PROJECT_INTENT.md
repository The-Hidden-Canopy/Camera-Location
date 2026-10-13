# Camera-Location — Project Intent

## Read This Before Changing Discovery or Remediation Logic

`Camera-Location` is the physical-infrastructure discovery and location utility for cameras, NVRs, radios, switches, edge hosts, and legacy devices.

It exists to preserve the difference between what the network reports, what an operator observes, what has been physically verified, and what has actually been authorized.

## Deeper Intent

Physical infrastructure is the reality check for the broader portfolio.

A dashboard may say a device exists. A vendor may say a relay is legitimate. An NVR may say a camera disappeared. A port scan may reveal something else.

The system must preserve the distinctions:

```text
declared state
observed state
verified state
authorized state
```

Discovery should create evidence, not trust by assumption.

## What This Repository Protects

- subnet observations;
- ARP, ONVIF, SADP, RTSP, and port-probe evidence;
- candidate device records;
- sequential and bounded scanning;
- operator-confirmed physical attribution;
- legacy-device investigation;
- recovery context;
- device-location lineage;
- non-destructive troubleshooting first.

## Boundary Rules

```text
device seen on network != trusted device
```

```text
IP address != durable identity
```

```text
discovery != authorization
```

```text
reachable device != safe remediation target
```

## Integration Boundary

```text
network observation
    -> DeviceDiscoveryCandidate
    -> operator verification
    -> PhysicalLocationVerificationEvent
    -> optional governed-authority event
```

An external facility-governance layer may assign trust and authorization. This
repository preserves the evidence required for that decision but does not
implement or imply that authority.

## Doctrine

```text
Preserve the observation.
Preserve the uncertainty.
Preserve the physical location evidence.
Preserve operator verification.
Do not confuse visibility with legitimacy.
```

## Related Documents

- [Open Canopy Contract](OPEN_CANOPY_CONTRACT.md)
- [Public change boundary](PUBLIC_CHANGE_BOUNDARY.md)
