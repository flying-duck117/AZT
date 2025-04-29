# Aerial Zero Trust Simulation + Raspberry Pi Implementation

This repository contains the implementation of the AZT security protocol for drone swarms, focusing on secure mobile ad hoc network (MANET) routing for UAVs.

## Requirements

- Python 3.9+
- Minikube with Kubernetes
- Docker
- kubectl

## Quick Start Guide

### First-Time Setup

For a new environment, use the `--startup` flag to initialize Minikube with the required components:

```bash
python3 run.py --startup
```

This will:
1. Start Minikube with the required network plugins
2. Apply Calico networking
3. Install MetalLB load balancer
4. Set up basic configurations

After the first time, you will not need to run --startup again until the cluster is shutdown.

### Running the Simulation

The basic command to run the simulation is:

```bash
python3 run.py
```

Note: When attempting to spin up a new configuration after a previous one you must run:

```bash
kubectl delete pods & kubectl delete svc & kubectl delete networkpolicies
```

This removes previous nodes and services.

### Available Topology Types

The simulation supports different drone arrangements:

1. **Multi-Swarm** (`--grid_type=multi_swarm`): Two distinct swarms with dedicated leaders (drones 1 and 6)
2. **Large Hop Extended** (`--grid_type=large_hop_extended`): 21 drones arranged in a long path to test routing over many hops
3. **Random** (`--grid_type=random`): Randomized drone placement in the grid

Example:
```bash
python3 run.py --grid_type=multi_swarm --drone_count=10
```

### Common Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--drone_count` | Number of drones in simulation | 10 |
| `--grid_size` | Size of the grid (NxN) | 12 |
| `--tesla_disclosure_time` | Disclosure period (sec) for TESLA keys | 10 |
| `--max_hop_count` | Maximum hop count for routing | 25 |
| `--max_seq_count` | Maximum sequence numbers to store | 50 |
| `--timeout` | Request timeout (sec) | 30 |
| `--log_level` | Log verbosity (DEBUG, INFO, etc.) | DEBUG |
| `--leader_drones` | Comma-separated list of leader drone IDs | 1,5 |
| `--discovery_interval` | Neighbor discovery interval (sec) | 360 |
| `--enable_leader` | Enable leader election | True |
| `--controller_addr` | Controller address for coordination | auto-detected |

View all available options:
```bash
python3 run.py --help
```

## Moving Drones During Simulation

Once the simulation is running, you can interactively move drones in the grid:

1. The grid layout is displayed in the terminal
2. Enter move commands in the format: `<drone_number> <to_row> <to_column>`
3. Type `q` to quit the simulation

Example: `5 3 7` (Move drone 5 to position row 3, column 7)

## Docker Images

The simulation uses two main Docker images:

1. **Drone Image**: `cyu72/drone:simulation-terminal`
   - Runs the C++ drone routing implementation
   - Handles network communication and protocol operations

2. **GCS Image**: `cyu72/gcs:simulation`
   - Ground Control Station that manages certificates
   - Handles initial authentication for drones

## Kubernetes Management

| Action | Command |
|--------|---------|
| View all pods | `kubectl get pods` |
| View logs | `kubectl logs <pod-name>` |
| Connect to terminal | `kubectl attach -it <pod-name> -c terminal` |
| Delete all pods | `kubectl delete pods --all` |
| View network policies | `kubectl get networkpolicies` |

## Authentication Flow

1. Drones receive certificates from the GCS
2. When joining a subswarm, drones authenticate with leader using challenge-response
3. After successful authentication, leader distributes Valid Certificate List (VCL) and Certificate Revocation List (CRL)
4. For efficiency during temporary disconnections, a quick re-authentication mechanism uses single-use reconnection tokens

## Interacting with Swarm

You can view all logs of any node and initate RREQs/RERRs with the following commands:

To view logs of any node:
```bash
kubectl logs -f [drone_pod_name]
```
By default, nodes should be named drone(num)

To attach to the termminal of any node:
```bash
kubectl attach -it [drone_pod_name] -c terminal
```

## Troubleshooting

- If pods fail to start, check the Kubernetes pod status: `kubectl describe pod <pod-name>`
- For network connectivity issues, verify network policies are applied correctly
- Check the logs for specific error messages: `kubectl logs <pod-name> -c logs`

-------------

## Raspberry Pi Setup [In Progress]

- Raspberry Pi 4B or newer (Must include 802.11b wireless)
- MicroSD card
- Raspberry Pi OS 64-bit (Bookworm or newer)
- Docker

# Launching GCS node
1. Fill in allowed_devices.json with intended SN and eeprom_id
2. Run `docker compose -f docker-compose.gcs.yml up` within corresponding docker-compose file directory
3. Attach a terminal to the *logger* with `docker compose -f logs`

# Launching each node

1. Fill out config.env file
2. Run `docker compose up` within corresponding docker-compose file directory
3. Attach two seperate terminals to the *logger* with `docker compose -f logs` and *terminal* with `docker compose attach -it interactive`
