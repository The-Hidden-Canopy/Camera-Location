# Public Change Boundary

This document defines the public repository boundary for Camera-Location.
The application is a local discovery and evidence tool. Its public source
does not grant access to private authority services, private repositories,
credentials, device inventories, or deployment environments.

## Required First Read

Read [`PROJECT_INTENT.md`](PROJECT_INTENT.md) before modifying discovery logic, subnet scanning, ARP handling, ONVIF or SADP probes, location records, device remediation, or operator verification workflows.

For an integration change, document the external contract locally and keep
the integration optional. Do not add private service URLs, repository paths,
tokens, credentials, or copied private implementation code to this tree.

## Project Intent

`Camera-Location` is the physical-infrastructure discovery and location utility for cameras, NVRs, radios, switches, edge hosts, and legacy devices.

Its purpose is to identify network-visible devices, preserve discovery evidence, support physical-location verification, and produce governed candidate records without confusing observation with trust.

## This Repository Owns

- discovery evidence;
- candidate device records;
- subnet observations;
- sequential and bounded scan workflows;
- location-verification workflow;
- operator-confirmed physical attribution;
- network-observation packets.

## This Repository Does Not Own

- automatic trust assignment;
- regulated authority;
- destructive remediation without operator approval;
- the assumption that an IP address equals a durable identity;
- automatic promotion of discovered devices into an authorized facility registry.

## Required Boundary

```text
network observation
    -> DeviceDiscoveryCandidate
    -> operator verification
    -> PhysicalLocationVerificationEvent
    -> optional private governance system DeviceIdentityEvent
```

## Primary Outbound Packets

- `DeviceDiscoveryCandidate`
- `NetworkObservationEvent`
- `PhysicalLocationVerificationEvent`

## Primary Inbound Packets

- `FacilityRegistryProjection`
- `AuthorizedDeviceSnapshot`

## Non-Negotiable Rules

1. Device seen on network does not mean trusted device.
2. Discovery is not authorization.
3. IP address is not durable identity.
4. Preserve MAC, subnet, timestamp, probe type, evidence source, and operator verification separately.
5. Sequential scanning and bounded concurrency are preferred when broad discovery could overload systems.
6. Destructive actions require explicit operator approval and evidence.
7. Legacy devices remain untrusted until verified.

## Stop Condition

If a change affects trust assignment, identity authority, automated
remediation, model training, or facility authorization, stop and identify the
owning service before editing. Camera-Location may emit bounded evidence and
operator proposals; it must not silently claim or acquire that authority.
