import time, random
import argparse
import subprocess
import threading
import requests

from flask import Flask, request, jsonify
from kubernetes import client, config
from tabulate import tabulate
import colorama
from colorama import Fore, Back, Style

app = Flask(__name__)
colorama.init(autoreset=True)
matrix = []

parser = argparse.ArgumentParser(description='AZT Drone Security Protocol Controller')
parser.add_argument('--drone_count', type=int, default=10, help='Specify number of drones in simulation')
parser.add_argument('--startup', action='store_true', help='Complete initial startup process (minikube)')
parser.add_argument('--tesla_disclosure_time', type=int, default=30, help='Disclosure period in seconds of every TESLA key disclosure message')
parser.add_argument('--max_hop_count', type=int, default=25, help='Maximum number of nodes we can route messages through')
parser.add_argument('--max_seq_count', type=int, default=50, help='Maximum number of sequence numbers we can store')
parser.add_argument('--timeout', type=int, default=30, help='Timeout for each request')
parser.add_argument('--grid_size', type=int, default=12, help='Defines nxn sized grid.')
parser.add_argument('--grid_type', choices=['random', 'multi_swarm', 'large_hop_extended'], default='large_hop_extended',
                    help='Choose between random, large hop grid, multi-swarm, or large hop extended (21 hops) topology')
parser.add_argument('--log_level', choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL', 'TRACE'], default='DEBUG', help='Set the log level for the drone')
parser.add_argument('--simulation_level', choices=['kube', 'pi'], default='kube', help='Set the simulation level')
parser.add_argument('--SKIP_VERIFICATION', choices=['True', 'False'], default='True', help='Skip verification for certification yield')
parser.add_argument('--discovery_interval', type=int, default=360, help='Set the discovery interval for drone in seconds')
parser.add_argument('--enable_leader', type=str, default='True', help='Enable leader election')
parser.add_argument('--leader_drones', type=str, default='1,5',
                    help='Comma-separated list of drone IDs that should be leaders')
parser.add_argument('--controller_addr', type=str, help='Controller address for drone connection')
parser.add_argument('--trigger_rerr', choices=['True', 'False'], default=False, help='Allow RERRs to be triggered within RREQ route caching')
args = parser.parse_args()

# Global variables
processes = []
threads = []
all_leader_drones = []

def generate_random_matrix(n, numDrones):
    matrix = [[0] * n for _ in range(n)]
    drone_numbers = random.sample(range(1, numDrones + 1), numDrones)

    for num in drone_numbers:
        while True:
            row = random.randint(0, n - 1)
            col = random.randint(0, n - 1)
            if matrix[row][col] == 0:
                matrix[row][col] = num
                break

    return matrix

def generate_large_hop_extended_matrix(n, numDrones):
    array = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 16, 17, 18, 19, 20, 21, 9, 0, 0, 0, 0],
        [0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 13, 12, 11, 7, 10, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 3, 4, 5, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ]
        
    return array

def generate_multi_swarm_matrix(n, numDrones):
    matrix = [
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 2, 3, 0, 7, 8, 0, 0, 0],
      [0, 0, 0, 1, 4, 5, 10, 6, 9, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ]

    return matrix

def run_command(command, description="", add_to_processes=True):
    if description:
        print(f"{Fore.CYAN}{description}...{Style.RESET_ALL}")
        
    if add_to_processes:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        processes.append(process)
        output, error = process.communicate()
        return output.decode(), error.decode()
    else:
        try:
            result = subprocess.run(command, shell=True, check=False, capture_output=True, text=True)
            
            if result.returncode != 0:
                error_msg = f"Error: {result.stderr}"
                print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
                return False, error_msg
            else:
                if description:
                    print(f"{Fore.GREEN}{description} completed successfully{Style.RESET_ALL}")
                return True, result.stdout
                
        except Exception as e:
            error_msg = f"Command failed: {str(e)}"
            print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
            return False, error_msg

# Alias for backward compatibility
def run_kubectl_command(cmd, desc=""):
    return run_command(cmd, desc, add_to_processes=False)

def print_matrix(matrix):
    headers = [''] + [str(i) for i in range(len(matrix[0]))]

    # Define swarm ranges for multi_swarm topology
    swarm1_range = list(range(1, 6))  # Drone IDs 1-5
    swarm2_range = list(range(6, 11)) # Drone IDs 6-10

    # Check topology type
    multi_swarm_mode = hasattr(args, 'grid_type') and args.grid_type == 'multi_swarm'
    large_hop_extended_mode = hasattr(args, 'grid_type') and args.grid_type == 'large_hop_extended'

    table_data = []
    for i, row in enumerate(matrix):
        colored_row = [str(i)]
        for element in row:
            if element == 0:
                colored_row.append(f"{Fore.LIGHTBLACK_EX}{element:2}{Style.RESET_ALL}")
            elif multi_swarm_mode:
                # Color-code based on swarm
                if element in swarm1_range:
                    # Swarm 1 - green
                    colored_row.append(f"{Fore.GREEN}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
                elif element in swarm2_range:
                    # Swarm 2 - yellow
                    colored_row.append(f"{Fore.YELLOW}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
                else:
                    # Default for any other drones
                    colored_row.append(f"{Fore.BLUE}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
            elif large_hop_extended_mode:
                # Special coloring for large hop extended mode to show path progression
                # Color gradient from blue to red based on drone ID (1-21)
                if 1 <= element <= 7:  # First segment (blue to cyan)
                    colored_row.append(f"{Fore.BLUE}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
                elif 8 <= element <= 14:  # Middle segment (cyan to magenta)
                    colored_row.append(f"{Fore.CYAN}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
                else:  # Last segment (magenta to red)
                    colored_row.append(f"{Fore.MAGENTA}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
            else:
                # Standard display for other topologies
                colored_row.append(f"{Fore.GREEN}{Back.LIGHTWHITE_EX}{element:2}{Style.RESET_ALL}")
        table_data.append(colored_row)

    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

    # Custom legend based on topology mode
    if multi_swarm_mode:
        print(f"\n{Fore.CYAN}Legend:")
        print(f"{Fore.GREEN}{Back.LIGHTWHITE_EX} Swarm 1 {Style.RESET_ALL} | "
              f"{Fore.YELLOW}{Back.LIGHTWHITE_EX} Swarm 2 {Style.RESET_ALL} | "
              f"{Fore.LIGHTBLACK_EX}0{Style.RESET_ALL} Empty Space")
    elif large_hop_extended_mode:
        print(f"\n{Fore.CYAN}Legend:")
        print(f"{Fore.BLUE}{Back.LIGHTWHITE_EX} Start Path {Style.RESET_ALL} | "
              f"{Fore.CYAN}{Back.LIGHTWHITE_EX} Mid Path {Style.RESET_ALL} | "
              f"{Fore.MAGENTA}{Back.LIGHTWHITE_EX} End Path {Style.RESET_ALL} | "
              f"{Fore.LIGHTBLACK_EX}0{Style.RESET_ALL} Empty Space")
        print(f"{Fore.CYAN}This topology demonstrates routing through {args.drone_count} hops in a linear arrangement.")
    else:
        print(f"\n{Fore.CYAN}Legend: {Fore.GREEN}{Back.LIGHTWHITE_EX} Drone {Style.RESET_ALL} | "
              f"{Fore.LIGHTBLACK_EX}0{Style.RESET_ALL} Empty Space")

def get_neighbors(matrix, i, j):
    neighbors = []
    # Check cardinal directions (up, down, left, right)
    if i > 0 and matrix[i-1][j] != 0:  # Up
        neighbors.append(matrix[i-1][j])
    if i < len(matrix)-1 and matrix[i+1][j] != 0:  # Down
        neighbors.append(matrix[i+1][j])
    if j > 0 and matrix[i][j-1] != 0:  # Left
        neighbors.append(matrix[i][j-1])
    if j < len(matrix[i])-1 and matrix[i][j+1] != 0:  # Right
        neighbors.append(matrix[i][j+1])

    # Check diagonal directions
    if i > 0 and j > 0 and matrix[i-1][j-1] != 0:  # Upper-left
        neighbors.append(matrix[i-1][j-1])
    if i > 0 and j < len(matrix[i])-1 and matrix[i-1][j+1] != 0:  # Upper-right
        neighbors.append(matrix[i-1][j+1])
    if i < len(matrix)-1 and j > 0 and matrix[i+1][j-1] != 0:  # Lower-left
        neighbors.append(matrix[i+1][j-1])
    if i < len(matrix)-1 and j < len(matrix[i])-1 and matrix[i+1][j+1] != 0:  # Lower-right
        neighbors.append(matrix[i+1][j+1])

    return neighbors



def create_network_policies(matrix):
    """Generate Kubernetes NetworkPolicy resources for drone communication.
    
    This function creates network policies for each drone in the matrix, defining:
    1. Ingress rules - allowing traffic from GCS and neighboring drones
    2. Egress rules - allowing traffic to GCS and neighboring drones
    
    Note: After generation, the policies are fixed to ensure no incorrect 'from' fields
    appear in egress rules (Kubernetes only allows 'to' in egress).
    """
    policies = []

    # Get leader drones for special handling in multi-swarm mode
    leader_drone_ids = [int(id.strip()) for id in args.leader_drones.split(',')]
    leader_positions = []

    # Find positions of all leader drones in the matrix
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] in leader_drone_ids:
                leader_positions.append((matrix[i][j], i, j))

    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] != 0:
                neighbors = get_neighbors(matrix, i, j)

                # In multi-swarm mode, leaders can also communicate with other leaders
                if args.grid_type == 'multi_swarm' and matrix[i][j] in leader_drone_ids:
                    for leader_id, _, _ in leader_positions:
                        if leader_id != matrix[i][j] and leader_id not in neighbors:
                            neighbors.append(leader_id)

                    # Special case: Print connections between leaders
                    other_leaders = [lid for lid, _, _ in leader_positions if lid != matrix[i][j]]
                    if other_leaders:
                        print(f"{Fore.CYAN}Leader drone {matrix[i][j]} can communicate with leaders: {other_leaders}")

                # Create a different policy structure depending on whether the drone has neighbors
                base_policy = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-selector{matrix[i][j]}
spec:
  podSelector:
    matchLabels:
      app: drone{matrix[i][j]}
      tier: drone
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: gcs
    ports:
    - protocol: TCP
      port: 65456
    - protocol: UDP
      port: 65457
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 60137"""

                # The common ports configuration
                ports_config = """
    ports:
    - protocol: TCP
      port: 65456
    - protocol: UDP
      port: 65457
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 60137"""

                policy = base_policy

                if neighbors:
                    # Add neighbor connections (ingress) if drone has neighbors
                    policy += f"""
  - from:
    - podSelector:
        matchExpressions:
        - key: app
          operator: In
          values: [{', '.join([f'drone{n}' for n in neighbors])}]{ports_config}"""
                    
                    # Add neighbor connections (egress) - only use 'to' for egress rules
                    policy += f"""
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: gcs
  - to:
    - podSelector:
        matchExpressions:
        - key: app
          operator: In
          values: [{', '.join([f'drone{n}' for n in neighbors])}]
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns"""
                
                policies.append(policy)

    with open('etc/kubernetes/deploymentNetworkPolicy.yml', 'w') as file:
        file.write("\n---\n".join(policies))

def move_drone(matrix, drone, to_pos, update_network=True):
    to_i, to_j = to_pos
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] == drone:
                matrix[i][j] = 0
                matrix[to_i][to_j] = drone
                if update_network:
                    create_network_policies(matrix)
                return matrix
    raise ValueError(f"Drone {drone} not found in the matrix")

@app.route('/coords', methods=['GET'])
def get_coords():
    return jsonify({"matrix": matrix}), 200

@app.route('/update_coords', methods=['POST'])
def update_coords():
    global matrix
    message = request.json
    try:
        drone = int(message['drone-id'])
        to_i = int(float(message['x']))
        to_j = int(float(message['y']))

        if to_i < 0 or to_i >= len(matrix) or to_j < 0 or to_j >= len(matrix[0]):
            return jsonify({"error": f"Position ({to_i}, {to_j}) is out of bounds"}), 400

        current_pos = None
        for i in range(len(matrix)):
            for j in range(len(matrix[0])):
                if matrix[i][j] == drone:
                    current_pos = (i, j)
                    break
            if current_pos:
                break

        if current_pos and current_pos == (to_i, to_j):
            print_matrix(matrix)
            return jsonify({
                "message": "Drone is already at the requested position",
                "new_matrix": matrix
            }), 200

        if matrix[to_i][to_j] != 0:
            return jsonify({"error": f"Position ({to_i}, {to_j}) is not empty"}), 400

        try:
            matrix = move_drone(matrix, drone, (to_i, to_j))
            print(f"{Fore.GREEN}Drone {drone} moved to position ({to_i}, {to_j}){Style.RESET_ALL}")
            print(f"{Fore.GREEN}Matrix updated and network policies updated.{Style.RESET_ALL}")
            print_matrix(matrix)
            return jsonify({"message": "Coordinates updated successfully", "new_matrix": matrix}), 200
        except Exception as e:
            error_msg = f"Failed to update network policies: {str(e)}"
            print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
            return jsonify({"error": error_msg}), 500
    except KeyError as e:
        return jsonify({"error": f"Invalid request format. Missing key: {str(e)}"}), 400
    except ValueError as e:
        return jsonify({"error": f"Invalid value: {str(e)}. Please provide valid integer values."}), 400
    except IndexError:
        return jsonify({"error": "Invalid position. Please ensure all indices are within the matrix bounds."}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

def get_available_ips():
    """Get all available IP addresses for the server."""
    import socket
    
    # Get all available IP addresses
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    available_ips = ["127.0.0.1", local_ip]  # Always include localhost
    
    # Try to get all available IPs
    try:
        all_ips = socket.getaddrinfo(hostname, None)
        for ip_info in all_ips:
            ip = ip_info[4][0]
            if ip not in available_ips and not ip.startswith("fe80") and ":" not in ip:  # Filter out IPv6
                available_ips.append(ip)
    except:
        pass  # If we can't get additional IPs, just use what we have
    
    return available_ips

def run_flask_server():
    """Run the Flask coordinate server."""
    # Suppress Flask output by redirecting logging
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)  # Only show errors, not standard startup messages
    
    # Run Flask app without the verbose output
    print(f"{Fore.GREEN}Starting coordinate server on port 8080...{Style.RESET_ALL}")
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

def setup_port_forwarding(services):
    for service in services.items:
        if service.spec.type == "LoadBalancer" and service.metadata.name.startswith("drone"):
            drone_number = int(service.metadata.name.split("drone")[1].split("-")[0])
            nodePort = 30000 + drone_number
            command = f"kubectl port-forward svc/{service.metadata.name} {nodePort}:8080"
            thread = threading.Thread(target=run_command, args=(command,))
            thread.start()
            threads.append(thread)

def verify_drone_count_matches_topology():
    """Verify that the drone count matches the expected count for the chosen topology 
    and update routing parameters based on topology requirements."""
    
    # Define topology-specific configurations
    topology_configs = {
        'multi_swarm': {
            'drone_count': 10,
            'max_hop_count': 25,
            'max_seq_count': 50
        },
        'large_hop_extended': {
            'drone_count': 21,
            'max_hop_count': 25,
            'max_seq_count': 50
        },
        'random': {
            'drone_count': 10,
            'max_hop_count': 25,
            'max_seq_count': 50
        }
    }
    
    # Get the configuration for the selected topology
    topo_config = topology_configs.get(args.grid_type)
    if not topo_config:
        print(f"{Fore.RED}Warning: Unknown topology type: {args.grid_type}. Using default parameters.")
        return
    
    expected_count = topo_config['drone_count']
    
    # Check if parameters match the expected configuration
    params_match = (
        args.drone_count == topo_config['drone_count'] and
        args.max_hop_count == topo_config['max_hop_count'] and
        args.max_seq_count == topo_config['max_seq_count']
    )
    
    if not params_match:
        print(f"{Fore.YELLOW}Topology '{args.grid_type}' requires specific parameters:")
        print(f"{Fore.YELLOW}  - Drone count: {topo_config['drone_count']} (currently: {args.drone_count})")
        print(f"{Fore.YELLOW}  - Max hop count: {topo_config['max_hop_count']} (currently: {args.max_hop_count})")
        print(f"{Fore.YELLOW}  - Max seq count: {topo_config['max_seq_count']} (currently: {args.max_seq_count})")
        
        print(f"{Fore.YELLOW}Do you want to adjust these parameters to match the topology requirements? (yes/no):")
        user_input = input()
        if user_input.lower() == "yes":
            args.drone_count = topo_config['drone_count']
            args.max_hop_count = topo_config['max_hop_count']
            args.max_seq_count = topo_config['max_seq_count']
            print(f"{Fore.GREEN}Parameters adjusted to match '{args.grid_type}' topology requirements:")
            print(f"{Fore.GREEN}  - Drone count: {args.drone_count}")
            print(f"{Fore.GREEN}  - Max hop count: {args.max_hop_count}")
            print(f"{Fore.GREEN}  - Max seq count: {args.max_seq_count}")
        else:
            print(f"{Fore.YELLOW}Continuing with current parameters. This may cause unexpected behavior.")

def get_controller_address():
    """Get the controller address from command line args or prompt the user for input."""
    controller_addr = args.controller_addr
    
    if not controller_addr:
        # Display available IPs for convenience
        available_ips = get_available_ips()
        print(f"{Fore.CYAN}Available IP addresses for controller_addr:{Style.RESET_ALL}")
        for ip in available_ips:
            print(f"{Fore.YELLOW}  http://{ip}:8080{Style.RESET_ALL}")
        
        # Prompt for input
        print(f"{Fore.CYAN}Enter the controller address (you can use one of the IPs listed above):{Style.RESET_ALL}")
        controller_addr = input(f"{Fore.YELLOW}[default: localhost]: {Style.RESET_ALL}")
        if not controller_addr:
            controller_addr = "localhost"
        
    print(f"{Fore.GREEN}Using controller address: {controller_addr}{Style.RESET_ALL}")
    return controller_addr

def setup_deployment(controller_addr):
    """Setup drone and GCS deployment files."""
    droneNum = args.drone_count
    droneImage = "cyu72/drone:simulation-terminal"
    gcsImage = "cyu72/gcs:simulation"
    delim = "---\n"

    # Update leader drones based on topology selection
    if args.grid_type == 'multi_swarm':
        # For multi-swarm topology, we hardcode the leaders to match the topology
        args.leader_drones = '1,6'
        print(f"{Fore.CYAN}Multi-swarm topology selected. Leader drones set to: {args.leader_drones}")
    elif args.grid_type == 'large_hop_extended':
        # For large hop extended topology, set first node as the leader
        args.leader_drones = '1'
        print(f"{Fore.CYAN}Large hop extended topology selected. Leader drone set to: {args.leader_drones}")

    # Pre-format the leader drones list for environment variables
    leader_drone_ids = args.leader_drones.split(',')
    all_leader_drones = ','.join([f"drone{id.strip()}-service.default" for id in leader_drone_ids])
    formatted_leader_drones = all_leader_drones

    # Print topology and leader information
    print(f"{Fore.CYAN}Selected topology: {args.grid_type}")
    print(f"{Fore.CYAN}Leader drones: {args.leader_drones}")

    # Display additional topology information based on type
    if args.grid_type == 'multi_swarm':
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║           MULTI-SWARM TOPOLOGY              ║")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ • 2 distinct swarms with dedicated leaders  ║")
        print(f"{Fore.CYAN}║ • Leaders can communicate across swarms     ║")
        print(f"{Fore.CYAN}║ • Each swarm operates independently         ║")
        print(f"{Fore.CYAN}║ • Cross-swarm routing is enabled            ║")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════╝")
        print(f"{Fore.GREEN}Swarm 1 Leader: Drone 1 (left side)")
        print(f"{Fore.YELLOW}Swarm 2 Leader: Drone 6 (right side)")
    elif args.grid_type == 'large_hop_extended':
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║        LARGE HOP EXTENDED TOPOLOGY          ║")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ • 21 drones arranged in a linear path       ║")
        print(f"{Fore.CYAN}║ • Demonstrates routing through many hops    ║")
        print(f"{Fore.CYAN}║ • Tests protocol efficiency with long paths ║")
        print(f"{Fore.CYAN}║ • Max hop count: {args.max_hop_count}                      ║")
        print(f"{Fore.CYAN}║ • Max sequence count: {args.max_seq_count}                ║")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════╝")
    elif args.grid_type == 'hardcoded':
        print(f"\n{Fore.CYAN}╔════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║           HARDCODED TOPOLOGY                ║")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ • Single swarm with multiple leaders        ║")
        print(f"{Fore.CYAN}║ • Optimized for 10-node deployments         ║")
        print(f"{Fore.CYAN}║ • Demonstrates scalability                  ║")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════╝")

    gcs_ip = 'gcs-service.default' if args.simulation_level == 'kube' else 'localhost'

    with open('etc/kubernetes/droneDeployment.yml', 'w') as file:
        nodePort = 30001
        for num in range(1, droneNum + 1):
            # For multi-swarm mode, we need to provide additional environment variables
            is_leader = num in [int(id) for id in args.leader_drones.split(',')]

            # Additional environment variables for cross-swarm communication
            additional_env = ""
            if args.grid_type == 'multi_swarm' and is_leader:
                # Add environment variable with list of other swarm leaders
                other_leaders = [f"drone{id.strip()}-service.default" for id in args.leader_drones.split(',') if int(id.strip()) != num]
                other_leaders_str = ','.join(other_leaders)
                additional_env = f"""
        - name: OTHER_SWARM_LEADERS
          value: "{other_leaders_str}"
        - name: GRID_TYPE
          value: "{args.grid_type}" """

            drone = f"""apiVersion: v1
kind: Pod
metadata:
  name: drone{num}
  namespace: default
  labels:
    app: drone{num}
    tier: drone
spec:
  hostname: drone{num}
  containers:
    - name: logs
      image: {droneImage}
      imagePullPolicy: Always
      stdin: true
      tty: true
      env:
        - name: NODE_ID
          value: "{num}"
        - name: PORT
          value: "65456"
        - name: TESLA_DISCLOSE
          value: "{args.tesla_disclosure_time}"
        - name: MAX_HOP_COUNT
          value: "{args.max_hop_count}"
        - name: MAX_SEQ_COUNT
          value: "{args.max_seq_count}"
        - name: CONTROLLER_ADDR
          value: "{controller_addr}"
        - name: TIMEOUT_SEC
          value: "{args.timeout}"
        - name: LOG_LEVEL
          value: "{args.log_level}"
        - name: GCS_IP
          value: "{gcs_ip}"
        - name: DRONE_COUNT
          value: "{args.drone_count}"
        - name: DISCOVERY_INTERVAL
          value: "{args.discovery_interval}"
        - name: IS_LEADER
          value: "{'true' if is_leader else 'false'}"
        - name: ENABLE_LEADER
          value: "{args.enable_leader}"{additional_env}
        - name: TRIGGER_RERR
          value: "{args.trigger_rerr}"
        - name: NODE_IP
          value: "drone{num}-service.default"
        - name: SN
          value: "100000009e15344d"
        - name: EEPROM_ID
          value: "00005d5d9e15344d61eacbb2"
        - name: IS_SIM
          value: "true"
      ports:
        - name: action-port
          protocol: TCP
          containerPort: 65456
        - name: brdcst-port
          protocol: UDP
          containerPort: 65457
        - name: start-port
          protocol: TCP
          containerPort: 8080
        - name: ipc
          protocol: TCP
          containerPort: 60137

    - name: terminal
      image: cyu72/drone:latest
      imagePullPolicy: Always
      command: ["./drone_app", "--terminal"]
      stdin: true
      tty: true
      env:
        - name: ROUTING_HOST
          value: "localhost"
        - name: NODE_ID
          value: "{num}"
        - name: NODE_IP
          value: "drone{num}-service.default"
"""
            service = f"""apiVersion: v1
kind: Service
metadata:
  name: drone{num}-service
spec:
  externalTrafficPolicy: Local
  type: LoadBalancer
  selector:
    app: drone{num}
    tier: drone
  ports:
  - name: drone-port
    protocol: TCP
    port: 65456
    targetPort: 65456
  - name: udp-test-port
    protocol: UDP
    port: 65457
    targetPort: 65457
  - name: start-port
    protocol: TCP
    port: 8080
    targetPort: 8080
    nodePort: {nodePort}
"""
            file.write(drone)
            file.write(delim)
            file.write(service)
            file.write(delim)
            nodePort += 1

        # Leader drones are pre-formatted in the main function
        gcs = f"""apiVersion: v1
kind: Pod
metadata:
  name: gcs
  namespace: default
  labels:
    app: gcs
    tier: drone
spec:
  hostname: gcs
  containers:
    - name: gcs
      image: {gcsImage}
      imagePullPolicy: Always
      stdin: true
      tty: true
      env:
        - name: SKIP_VERIFICATION
          value: "{args.SKIP_VERIFICATION}"
        - name: LEADER_DRONES
          value: "{formatted_leader_drones}"
        - name: ALL_LEADER_DRONES
          value: "{all_leader_drones}"
      ports:
        - name: main-port
          protocol: TCP
          containerPort: 65456
        - name: udp-test-port
          protocol: UDP
          containerPort: 65457
        - name: flask-port
          protocol: TCP
          containerPort: 5000"""

        gcs_service = f"""apiVersion: v1
kind: Service
metadata:
  name: gcs-service
spec:
  type: LoadBalancer
  selector:
    app: gcs
    tier: drone
  ports:
  - name: gcs-port
    protocol: TCP
    port: 65456
    targetPort: 65456
  - name: udp-test-port
    protocol: UDP
    port: 65457
    targetPort: 65457
  - name: flask-port
    protocol: TCP
    port: 5000
    targetPort: 5000"""

        configMap = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: config
  namespace: metallb-system
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 192.168.1.101-192.168.1.150
"""

        file.write(gcs + "\n" + delim + gcs_service + "\n" + delim + configMap + "\n")
    
    return formatted_leader_drones, all_leader_drones

def handle_minikube_startup():
    """Handle minikube startup if needed."""
    if args.startup:
        subprocess.run("minikube start --insecure-registry='localhost:5001' --network-plugin=cni --cni=calico", shell=True, check=True)
        run_kubectl_command("kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.4/manifests/calico.yaml",
                        "Applying Calico networking")
        run_kubectl_command("kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml",
                        "Applying MetalLB load balancer")

        subprocess.run("minikube addons enable metallb", shell=True, check=True)
        time.sleep(45)  # Wait for everything to initialize

def generate_grid_layout():
    """Generate and validate the grid layout for drones."""
    valid_config = False
    global matrix
    
    while not valid_config:
        if args.grid_type == 'random':
            matrix = generate_random_matrix(args.grid_size, args.drone_count)
        elif args.grid_type == 'multi_swarm':
            matrix = generate_multi_swarm_matrix(args.grid_size, args.drone_count)
        elif args.grid_type == 'large_hop_extended':
            matrix = generate_large_hop_extended_matrix(args.grid_size, args.drone_count)

        print_matrix(matrix)

        user_input = input("Is this a valid configuration? (yes/no): ")
        if user_input.lower() == "yes":
            valid_config = True
            create_network_policies(matrix)
    
    return matrix

def wait_for_pods(droneNum):
    """Wait for all drone pods to be ready."""
    print(f"{Fore.CYAN}Waiting for drone pods to be ready...{Style.RESET_ALL}")
    ready_drones = 0

    for num in range(1, droneNum + 1):
        wait_command = f"kubectl wait --for=condition=ready pod drone{num} --timeout=120s"
        success, output = run_kubectl_command(wait_command, f"Waiting for Drone{num}")

        if success:
            print(f"{Fore.GREEN}Drone{num} is ready{Style.RESET_ALL}")
            ready_drones += 1
        else:
            print(f"{Fore.YELLOW}Warning: Timeout waiting for drone{num}{Style.RESET_ALL}")

    # Summary of readiness
    if ready_drones == droneNum:
        print(f"{Fore.GREEN}All {droneNum} drones are ready!{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Only {ready_drones} out of {droneNum} drones are ready. Proceeding anyway...{Style.RESET_ALL}")

def display_leader_drones(matrix):
    """Display information about leader drones."""
    leader_drones_ids = [int(id) for id in args.leader_drones.split(',')]
    leader_drones = []
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] != 0 and matrix[i][j] in leader_drones_ids:
                leader_drones.append((matrix[i][j], i, j))

    # Display leader information with color-coded swarm identification
    if args.grid_type == 'multi_swarm':
        print(f"{Fore.CYAN}Selected leader drones (drone_id, row, col):")
        for leader in leader_drones:
            if leader[0] == 1:
                swarm_color = Fore.GREEN
                swarm_name = "Swarm 1 (left side)"
            elif leader[0] == 6:
                swarm_color = Fore.YELLOW
                swarm_name = "Swarm 2 (right side)"
            else:
                swarm_color = Fore.WHITE
                swarm_name = "Unknown swarm"

            print(f"{swarm_color}  Drone {leader[0]} at position ({leader[1]},{leader[2]}) - {swarm_name}{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}Selected leader drones: {leader_drones}{Style.RESET_ALL}")

def handle_drone_movement(matrix):
    """Handle interactive drone movement."""
    config.load_kube_config()
    api_instance = client.CoreV1Api()
    services = api_instance.list_service_for_all_namespaces()
    
    while True:
        print_matrix(matrix)
        user_input = input("Enter move (drone_number to_i to_j) or 'q' to quit: ")

        if user_input.lower() == 'q':
            func = request.environ.get('werkzeug.server.shutdown')
            if func is None:
                raise RuntimeError('Not running with the Werkzeug Server')
            func()
            break

        try:
            drone, to_i, to_j = map(int, user_input.split())
            if matrix[to_i][to_j] != 0:
                print(f"{Fore.RED}Error: Position ({to_i}, {to_j}) is not empty{Style.RESET_ALL}")
                continue

            try:
                # Record the old position for potential rollback
                old_positions = {}
                for i in range(len(matrix)):
                    for j in range(len(matrix[i])):
                        if matrix[i][j] == drone:
                            old_positions = {'drone': drone, 'i': i, 'j': j}
                            break
                    if old_positions:
                        break

                # Attempt to move the drone with network policy update
                try:
                    matrix = move_drone(matrix, drone, (to_i, to_j), update_network=True)
                    print(f"{Fore.GREEN}Drone {drone} moved to position ({to_i}, {to_j}){Style.RESET_ALL}")
                    run_kubectl_command("kubectl apply -f etc/kubernetes/deploymentNetworkPolicy.yml", "Applying network policies")
                    print(f"{Fore.GREEN}Network policies updated successfully{Style.RESET_ALL}")
                except Exception as policy_error:
                    # If updating policies fails, roll back the drone movement
                    if old_positions:
                        print(f"{Fore.YELLOW}Rolling back drone movement due to policy error...{Style.RESET_ALL}")
                        matrix[old_positions['i']][old_positions['j']] = old_positions['drone']
                        matrix[to_i][to_j] = 0
                        print(f"{Fore.YELLOW}Drone {drone} movement rolled back to original position{Style.RESET_ALL}")
                    raise policy_error

            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        except ValueError as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        except IndexError:
            print(f"{Fore.RED}Invalid position. Please ensure all indices are within the matrix bounds.{Style.RESET_ALL}")

def main():
    global matrix, processes, threads, all_leader_drones
    processes = []
    threads = []
    
    print(f"{Fore.CYAN}=== AZT Drone Security Protocol Controller Setup ==={Style.RESET_ALL}")
    
    # Verify drone count matches the expected count for the chosen topology
    verify_drone_count_matches_topology()
    
    # Get controller address (with available IPs)
    controller_addr = get_controller_address()
    
    # Setup deployment files and get leader drones info
    formatted_leader_drones, all_leader_drones = setup_deployment(controller_addr)
    
    # Handle minikube startup if needed
    handle_minikube_startup()
    
    # Generate grid layout
    matrix = generate_grid_layout()
    
    print(f"{Fore.CYAN}=== Starting Network Services ==={Style.RESET_ALL}")
    
    # Start the Flask server
    flask_thread = threading.Thread(target=run_flask_server)
    flask_thread.daemon = True  
    flask_thread.start()
    
    # Give Flask a moment to start up
    time.sleep(1)
    
    # Apply drone deployment
    run_kubectl_command("kubectl apply -f etc/kubernetes/droneDeployment.yml", "Applying drone deployment")
    run_kubectl_command("kubectl apply -f etc/kubernetes/deploymentNetworkPolicy.yml", "Applying network policies")
    
    # Wait for pods
    time.sleep(20)
    wait_for_pods(args.drone_count)
    
    # Wait for pods to be ready and monitor their status
    while True:
        config.load_kube_config()
        api_instance = client.CoreV1Api()
        
        pods = api_instance.list_pod_for_all_namespaces(watch=False)
        services = api_instance.list_service_for_all_namespaces()
        
        all_running = True
        for pod in pods.items:
            if pod.status.phase != "Running":
                all_running = False
                time.sleep(2)
                break
        
        if all_running:
            print(f"{Fore.GREEN}All pods are running{Style.RESET_ALL}")
            setup_port_forwarding(services)
            display_leader_drones(matrix)
            break
        else:
            print(f"{Fore.YELLOW}Not all pods are running. Waiting...{Style.RESET_ALL}")
            time.sleep(5)
    
    # Handle drone movement
    handle_drone_movement(matrix)
    
    # Clean up
    for thread in threads:
        thread.join(timeout=0.5)
    
    for process in processes:
        try:
            process.terminate()
        except:
            pass

    # Clean up Kubernetes resources before the program ends
    print(f"{Fore.CYAN}Cleaning up Kubernetes resources...{Style.RESET_ALL}")
    run_kubectl_command("kubectl delete pods --all &", "Deleting all pods")
    run_kubectl_command("kubectl delete svc --all &", "Deleting all services")
    run_kubectl_command("kubectl delete networkpolicies --all &", "Deleting all network policies")
    print(f"{Fore.GREEN}Cleanup completed.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()