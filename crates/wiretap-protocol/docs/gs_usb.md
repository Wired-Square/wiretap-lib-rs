# gs_usb (candleLight) USB protocol

**Source:** the Linux kernel driver,
[`drivers/net/can/usb/gs_usb.c`](https://github.com/torvalds/linux/blob/master/drivers/net/can/usb/gs_usb.c)
(GPL-2.0, Maximilian Schneider).

gs_usb is the USB protocol the kernel's driver speaks to the Geschwister
Schneider USB/CAN device. Compatible firmware — candleLight, on STM32 parts —
makes a CANable or CANable Pro look like one. On Linux the kernel claims the
device and an application sees SocketCAN instead; on Windows and macOS there is
no such driver, so an application drives the endpoints itself.

The [`gs_usb`](../src/gs_usb.rs) module implements the layouts and the bit
timing maths for that second case. What it implements is
[§6](#6-what-this-crate-implements).

---

## 1. General structure

Control transfers (EP0) configure; bulk transfers carry frames. All multi-byte
fields are little-endian, and the device is told so explicitly ([§3.2](#32-host_format-request-0)).
There are no checksums — USB provides integrity.

```
Configuration:  USB control transfer (EP0)
Frame RX:       USB bulk IN  (EP1, 0x81)
Frame TX:       USB bulk OUT (EP2, 0x02)
```

---

## 2. USB identification

| Field | Value | Device |
|-------|-------|--------|
| VID | `0x1D50` | OpenMoko Inc. |
| PID | `0x606F` | Geschwister Schneider USB/CAN, candleLight |
| PID | `0x606D` | CANable (candleLight firmware) |

A USB serial number, where a device has one, is a stabler identifier than
bus:address — the latter changes on re-enumeration.

---

## 3. Control requests

Vendor-type requests to the interface recipient. `wValue` carries the CAN
channel index; `wIndex` is 0 unless noted.

### 3.1 Request types

| Request | Code | Direction | Payload | Meaning |
|---------|------|-----------|---------|---------|
| `HOST_FORMAT` | 0 | OUT | 4 | byte-order negotiation |
| `BITTIMING` | 1 | OUT | 20 | nominal (arbitration) bit timing |
| `MODE` | 2 | OUT | 8 | start/stop, operating mode |
| `BERR` | 3 | IN | — | bus error reporting |
| `BT_CONST` | 4 | IN | 40 | timing constraints and feature flags |
| `DEVICE_CONFIG` | 5 | IN | 12 | channel count, versions |
| `TIMESTAMP` | 6 | IN | — | hardware timestamp |
| `IDENTIFY` | 7 | OUT | — | blink an LED |
| `GET_USER_ID` | 8 | IN | — | read a user-defined id |
| `SET_USER_ID` | 9 | OUT | — | write one |
| `DATA_BITTIMING` | 10 | OUT | 20 | CAN FD data-phase timing |
| `BT_CONST_EXT` | 11 | IN | 72 | nominal *and* data-phase constraints |
| `SET_TERMINATION` | 12 | OUT | — | bus termination resistor |
| `GET_TERMINATION` | 13 | IN | — | its state |
| `GET_STATE` | 14 | IN | — | CAN controller state |

### 3.2 HOST_FORMAT (request 0)

Sent first. The payload is `0x0000BEEF` little-endian; a device that reads it
byte-swapped knows to swap everything else.

```
wValue: 1
wIndex: channel
Data:   [0xEF, 0xBE, 0x00, 0x00]
```

### 3.3 DEVICE_CONFIG (request 5)

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────
0–2     3     Reserved
3       1     icount: channel count MINUS ONE (0 means one channel)
4–7     4     Software version: u32 LE
8–11    4     Hardware version: u32 LE
```

### 3.4 BT_CONST (request 4)

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────
0–3     4     Feature flags (§3.6)
4–7     4     CAN clock frequency in Hz, e.g. 48000000
8–11    4     tseg1_min
12–15   4     tseg1_max
16–19   4     tseg2_min
20–23   4     tseg2_max
24–27   4     sjw_max
28–31   4     brp_min
32–35   4     brp_max
36–39   4     brp_inc
```

Firmware that means "one" reports `brp_inc` as 0.

### 3.5 BT_CONST_EXT (request 11)

The same 40 bytes, then the data-phase constraints — usually much tighter than
the nominal ones. Only on devices advertising the `BT_CONST_EXT` feature.

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────
0–39    40    Nominal phase, exactly as §3.4
40–43   4     dtseg1_min
44–47   4     dtseg1_max
48–51   4     dtseg2_min
52–55   4     dtseg2_max
56–59   4     dsjw_max
60–63   4     dbrp_min
64–67   4     dbrp_max
68–71   4     dbrp_inc
```

### 3.6 Feature flags

| Bit | Value | Name |
|-----|-------|------|
| 0 | `0x0001` | `LISTEN_ONLY` |
| 1 | `0x0002` | `LOOP_BACK` |
| 2 | `0x0004` | `TRIPLE_SAMPLE` |
| 3 | `0x0008` | `ONE_SHOT` |
| 4 | `0x0010` | `HW_TIMESTAMP` |
| 5 | `0x0020` | `IDENTIFY` |
| 6 | `0x0040` | `USER_ID` |
| 7 | `0x0080` | `PAD_PKTS_TO_MAX_PKT_SIZE` |
| 8 | `0x0100` | `FD` |
| 9 | `0x0200` | `REQ_USB_QUIRK_LPC546XX` |
| 10 | `0x0400` | `BT_CONST_EXT` |
| 11 | `0x0800` | `TERMINATION` |
| 12 | `0x1000` | `BERR_REPORTING` |
| 13 | `0x2000` | `GET_STATE` |

### 3.7 BITTIMING (request 1) and DATA_BITTIMING (request 10)

The same 20-byte structure for either phase:

```
Offset  Size  Description
──────  ────  ──────────────────────────────
0–3     4     prop_seg
4–7     4     phase_seg1
8–11    4     phase_seg2
12–15   4     sjw
16–19   4     brp
```

```
bitrate      = fclk_can / (brp × (1 + prop_seg + phase_seg1 + phase_seg2))
sample_point =            (1 + prop_seg + phase_seg1) / (that same total)
```

87.5% is the usual nominal sample point; an FD data phase wants something lower,
commonly 75%.

### 3.8 MODE (request 2)

```
Offset  Size  Description
──────  ────  ──────────────────────────────
0–3     4     Mode: 0 = reset/stop, 1 = start
4–7     4     Mode flags
```

| Bit | Value | Name |
|-----|-------|------|
| 0 | `0x0001` | `LISTEN_ONLY` — no ACK, no transmit |
| 1 | `0x0002` | `LOOP_BACK` |
| 2 | `0x0004` | `TRIPLE_SAMPLE` |
| 3 | `0x0008` | `ONE_SHOT` — no automatic retransmission |
| 4 | `0x0010` | `HW_TIMESTAMP` |
| 7 | `0x0080` | `PAD_PKTS_TO_MAX_PKT_SIZE` |
| 8 | `0x0100` | `FD` |

---

## 4. Host frames

The same layout in both directions: the device sends these on bulk IN and reads
them from bulk OUT.

### 4.1 Classic (20 bytes)

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────
0–3     4     echo_id: 0xFFFFFFFF = received; anything else = a TX echo
4–7     4     can_id: arbitration id with flags (§4.3)
8       1     can_dlc: 0–8 — here a code and a byte count alike
9       1     channel: 0-based
10      1     flags (§4.4)
11      1     reserved
12–19   8     data, zero-padded
```

### 4.2 CAN FD (76 bytes)

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────
0–3     4     echo_id
4–7     4     can_id
8       1     can_dlc: 0–15, a data length CODE (§4.6)
9       1     channel
10      1     flags
11      1     reserved
12–75   64    data, zero-padded
```

**`can_dlc` is a code on an FD frame.** The kernel calls `can_fd_len2dlc` on the
way out and `can_fd_dlc2len` on the way back. Below 9 bytes the two are the same
number, which is why writing a byte count there is invisible until someone sends
a 12-byte frame — and then the device transmits 24.

### 4.3 CAN id encoding

| Bit(s) | Mask | Meaning |
|--------|------|---------|
| 31 | `0x80000000` | extended (29-bit) id |
| 30 | `0x40000000` | remote transmission request |
| 29 | `0x20000000` | error frame |
| 28–0 | `0x1FFFFFFF` | the arbitration id |

This is a SocketCAN id, carried verbatim.

### 4.4 Frame flags

| Bit | Value | Name |
|-----|-------|------|
| 0 | `0x01` | `FD` |
| 1 | `0x02` | `BRS` — bit rate switch |
| 2 | `0x04` | `ESI` — error state indicator |

Some firmware does not set `FD` on a *received* frame. A reader that trusts the
flag alone truncates such a frame to 8 bytes; a length code above 8 cannot occur
on a classic frame, so it is a sound fallback.

### 4.5 Echo id

`0xFFFFFFFF` means the frame came off the bus. Anything else is the device
returning a frame the host transmitted, carrying whatever `echo_id` the host
assigned — which is how the kernel driver tracks in-flight transmissions.

### 4.6 CAN FD length codes (ISO 11898-2:2015)

| Code | Bytes | | Code | Bytes |
|------|-------|-|------|-------|
| 0–8 | 0–8 | | 12 | 24 |
| 9 | 12 | | 13 | 32 |
| 10 | 16 | | 14 | 48 |
| 11 | 20 | | 15 | 64 |

### 4.7 Packet padding

A device advertising `PAD_PKTS_TO_MAX_PKT_SIZE` pads bulk transfers to the USB
maximum packet size. **That size is not fixed** — it is read from the bulk IN
endpoint descriptor. 32 bytes (full speed) and 512 (high speed) are common, but
the device decides.

So a reader parsing several frames out of one transfer strides by the max packet
size when padding is on, and by the native frame size (20 or 76) when it is not.

---

## 5. Initialisation

```
1. HOST_FORMAT       byte order
2. BT_CONST          feature flags, clock, nominal constraints
3. MODE (reset)      mode 0, flags 0
4. BITTIMING         nominal timing, calculated from bitrate and sample point
5. BT_CONST_EXT      data-phase constraints — only for FD, only if advertised
6. DATA_BITTIMING    data-phase timing — only for FD
7. MODE (start)      mode 1, with the mode flags
```

Stopping is `MODE` with mode 0.

---

## 6. What this crate implements

The layouts and the timing maths, in [`gs_usb`](../src/gs_usb.rs). Driving the
USB endpoints is the caller's.

| | Item |
|---|---|
| Identity | `VID`, `PIDS`, `HOST_FORMAT`, `ECHO_ID_RX` |
| Requests | `Breq` |
| Flags | `can_mode`, `can_feature`, `fd_flags`, `id_flags` |
| Frames | `HostFrame`, `parse_host_frame`, `encode_host_frame_into`, `HostFrame::transmit` |
| Replies | `DeviceConfig`, `BtConst`, `BtConstExtended`, `BittimingConstraints` |
| Requests out | `Bittiming::to_bytes`, `Mode::to_bytes` |
| Timing | `calculate_bittiming`, `PERMISSIVE_CONSTRAINTS`, `bittiming_for_bitrate` |

`calculate_bittiming` scores every arrangement that fits and returns the closest
on bitrate, then on sample point — rather than the first that merely fits, which
made the answer depend on the order the quanta counts happened to be written in.
`bittiming_for_bitrate` is a last resort for firmware that will not report its
clock, and is only right at 48 MHz.

Nothing here reads or writes `BERR`, `TIMESTAMP`, `IDENTIFY`, the user id, the
termination control or `GET_STATE`.
