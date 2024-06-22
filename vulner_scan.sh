!/bin/bash

# Check if the script is run as root
if [ "$(whoami)" != "root" ]; then
    echo "Ф This script must be run as root."
    exit 1
fi

# Ask the user if they want to check for updates
read -p "Do you want to check for updates? (y/n): " check_updates
if [[ "$check_updates" =~ ^(y|Y)$ ]]; then
    echo "Ф Checking for updates..."
    apt-get update
    apt-get upgrade -y
    echo "Ф System is up to date."
fi

# Function to validate network input
validate_network() {
    local network=$1
    if [[ $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[01])$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate scan type
validate_scan_type() {
    local scan_type=$1
    if [[ $scan_type =~ ^(basic|full|b|f)$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to normalize scan type input
normalize_scan_type() {
    local scan_type=$1
    if [[ $scan_type =~ ^(b|basic)$ ]]; then
        echo "Basic"
    elif [[ $scan_type =~ ^(f|full)$ ]]; then
        echo "Full"
    fi
}

# Create a built-in password list
create_builtin_password_list() {
    local file=$1
    cat <<EOF > "$file"
123456
password
123456789
12345678
12345
1234567
1234
qwerty
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
password1
admin
welcome
login
1q2w3e4r
admin123
123qwe
mynoob
123abc
1234567890
zaq12wsx
qazwsx
password123
EOF
}

# Create a built-in username list
create_builtin_username_list() {
    local file=$1
    cat <<EOF > "$file"
root
admin
guest
test
administrator
support
user1
demo
test1
operator
staff
manager
student
backup
info
marketing
office
sales
webmaster
postmaster
EOF
}

# Get the network to scan from the user
read -p "Enter the network to scan (e.g., 192.168.1.0/24): " network
while ! validate_network $network; do
    echo "Invalid network format. Please enter a valid CIDR range between 1 and 31."
    read -p "Enter the network to scan (e.g., 192.168.1.0/24): " network
done

# Get the name for the output directory from the user
read -p "Enter the name for the output directory: " output_dir
while [[ -z $output_dir ]]; do
    echo "Output directory name cannot be empty. Please try again."
    read -p "Enter the name for the output directory: " output_dir
done

# Get the scan type from the user
read -p "Choose the scan type ('Basic' or 'Full'): " scan_type
scan_type=$(echo $scan_type | tr '[:upper:]' '[:lower:]') # Normalize to lowercase
while ! validate_scan_type $scan_type; do
    echo "Invalid scan type. Please choose 'Basic' or 'Full'."
    read -p "Choose the scan type ('Basic' or 'Full'): " scan_type
    scan_type=$(echo $scan_type | tr '[:upper:]' '[:lower:]') # Normalize to lowercase
done

# Normalize the scan type for consistent processing
scan_type=$(normalize_scan_type $scan_type)

# If full scan, ask if user wants to run additional NSE scripts
run_nbstat="n"
run_smb_suite="n"
run_mssql_info="n"
if [ "$scan_type" == "Full" ]; then
    read -p "Do you want to run nbstat? (y/n): " run_nbstat
    run_nbstat=$(echo $run_nbstat | tr '[:upper:]' '[:lower:]')
    read -p "Do you want to run the SMB Suite (smb-enum-users and smb-enum-shares)? (y/n): " run_smb_suite
    run_smb_suite=$(echo $run_smb_suite | tr '[:upper:]' '[:lower:]')
    read -p "Do you want to run ms-sql-info? (y/n): " run_mssql_info
    run_mssql_info=$(echo $run_mssql_info | tr '[:upper:]' '[:lower:]')
fi

# Display the user input
echo "Network to scan: $network"
echo "Output directory: $output_dir"
echo "Scan type: $scan_type"

# Create the output directory
mkdir -p "$output_dir"
echo "Output directory '$output_dir' created."

# Save the input to a file for later use
echo "Network: $network" > "$output_dir/input.txt"
echo "Output directory: $output_dir" >> "$output_dir/input.txt"
echo "Scan type: $scan_type" >> "$output_dir/input.txt"

# Function to create a default user list
create_default_user_list() {
    local file=$1
    create_builtin_username_list "$file"
}

# Get username or user list for Hydra
read -p "Do you want to supply your own user list? (y/n): " user_user_list
if [[ "$user_user_list" =~ ^(y|Y)$ ]]; then
    read -p "Enter the path to your user list: " user_user_list_path
    if [ ! -f "$user_user_list_path" ]; then
        echo "Ф The specified user list file does not exist. QUITTING!"
        exit 1
    fi
    cp "$user_user_list_path" "$output_dir/user.lst"
    echo "User list copied to $output_dir/user.lst"
else
    create_default_user_list "$output_dir/user.lst"
    echo "Using default user list for Hydra."
fi

# Create built-in password list
builtin_password_list="$output_dir/builtin_password.lst"
create_builtin_password_list "$builtin_password_list"

# User-supplied password list (if provided)
read -p "Do you want to supply your own password list? (y/n/rockyou): " user_password_list
if [[ "$user_password_list" =~ ^(y|Y)$ ]]; then
    read -p "Enter the path to your password list: " user_password_list_path
    if [ ! -f "$user_password_list_path" ]; then
        echo "Ф The specified password list file does not exist. QUITTING!"
        exit 1
    fi
    cp "$user_password_list_path" "$output_dir/user_password.lst"
    echo "User password list copied to $output_dir/user_password.lst"
elif [[ "$user_password_list" =~ ^(rockyou|R)$ ]]; then
    if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
        echo "Ф Rockyou wordlist not found. Please install it and try again."
        exit 1
    fi
    cp "/usr/share/wordlists/rockyou.txt" "$output_dir/user_password.lst"
    echo "Rockyou password list copied to $output_dir/user_password.lst"
else
    echo "Using built-in password list."
fi

# Initialize scan log
scan_log="$output_dir/scan.log"
echo "Scan log created at $scan_log" > "$scan_log"

# Function to perform the network scan
perform_network_scan() {
    echo "Ф Starting network scan..."
    if [ "$scan_type" == "Basic" ]; then
        echo "Ф Running basic network scan..."
        nmap -sS -sU -version-intensity 0 -v $network -oG "$output_dir/nmap_scan.gnmap" >> "$scan_log" 2>&1
        echo "Ф Basic scan completed. Results saved to $scan_log"
    else
        echo "Ф Running full network scan..."
        nmap -sS -sU -version-intensity 0 -A -v $network --script vuln -oG "$output_dir/nmap_scan.gnmap" >> "$scan_log" 2>&1
        echo "Ф Full scan completed. Results saved to $scan_log"
    fi
}

# Perform network scan
perform_network_scan

# Function to extract open ports from Nmap scan
extract_open_ports() {
    local service=$1
    local port=$2
    grep " $port/open" "$output_dir/nmap_scan.gnmap" | awk '{print $2}'
}

# Function to extract live hosts from Nmap scan
extract_live_hosts() {
    grep 'Status: Up' "$output_dir/nmap_scan.gnmap" | awk '{print $2}' > "$output_dir/live_hosts.txt"
}

# Perform additional scans if user agreed
if [ "$run_nbstat" == "y" ]; then
    echo "Ф Running nbstat..."
    nmap --script nbstat -v $network >> "$output_dir/nbstat_results.txt" 2>&1
    echo "Ф nbstat completed. Results saved to $output_dir/nbstat_results.txt"
fi

if [ "$run_smb_suite" == "y" ]; then
    echo "Ф Running SMB Suite (smb-enum-users and smb-enum-shares)..."
    nmap --script smb-enum-users,smb-enum-shares -v $network >> "$output_dir/smb_suite_results.txt" 2>&1
    echo "Ф SMB Suite completed. Results saved to $output_dir/smb_suite_results.txt"
fi

if [ "$run_mssql_info" == "y" ]; then
    echo "Ф Running ms-sql-info..."
    nmap --script ms-sql-info -v $network >> "$output_dir/mssql_info_results.txt" 2>&1
    echo "Ф ms-sql-info completed. Results saved to $output_dir/mssql_info_results.txt"
fi

# Function to check for weak passwords with Hydra
check_weak_passwords_hydra() {
    local service=$1
    local port=$2
    local service_dir="$output_dir/$service"
    mkdir -p "$service_dir"

    echo "Ф Checking for weak passwords on $service with Hydra..."

    if [ -f "$output_dir/user_password.lst" ]; then
        password_list="$output_dir/user_password.lst"
    else
        password_list="$builtin_password_list"
    fi

    echo "Ф Running weak password check for $service with Hydra..."
    if [ "$service" == "ssh" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/hydra_weak_passwords_${service}_${ip}.txt"
            hydra -L "$output_dir/user.lst" -P "$password_list" -t 8 -w 30 -o "$output_file" -f -u $ip ssh -s $port >> "$service_dir/hydra_$service.log" 2>&1
        done
    elif [ "$service" == "ftp" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/hydra_weak_passwords_${service}_${ip}.txt"
            hydra -L "$output_dir/user.lst" -P "$password_list" -t 8 -w 30 -o "$output_file" -f -u $ip ftp -s $port >> "$service_dir/hydra_$service.log" 2>&1
        done
    elif [ "$service" == "telnet" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/hydra_weak_passwords_${service}_${ip}.txt"
            hydra -L "$output_dir/user.lst" -P "$password_list" -t 8 -e n -w 30 -o "$output_file" -f -u $ip telnet -s $port >> "$service_dir/hydra_$service.log" 2>&1
        done
    elif [ "$service" == "rdp" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/hydra_weak_passwords_${service}_${ip}.txt"
            hydra -L "$output_dir/user.lst" -P "$password_list" -t 8 -w 30 -o "$output_file" -f -u $ip rdp -s $port >> "$service_dir/hydra_$service.log" 2>&1
        done
    fi

    if [ -s "$output_file" ]; then
        echo "Ф Weak password check for $service with Hydra completed. Results saved to the output folder"
    else
        echo "Ф No weak passwords found for $service with Hydra."
    fi
}

# Function to check for weak passwords with Medusa
check_weak_passwords_medusa() {
    local service=$1
    local port=$2
    local service_dir="$output_dir/$service"
    mkdir -p "$service_dir"

    echo "Ф Checking for weak passwords on $service with Medusa..."

    if [ -f "$output_dir/user_password.lst" ]; then
        password_list="$output_dir/user_password.lst"
    else
        password_list="$builtin_password_list"
    fi

    echo "Ф Running weak password check for $service with Medusa..."
    if [ "$service" == "ssh" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/medusa_weak_passwords_${service}_${ip}.txt"
            medusa -U "$output_dir/user.lst" -P "$password_list" -h $ip -M ssh -n $port -f -O "$output_file" >> "$service_dir/medusa_$service.log" 2>&1
        done
    elif [ "$service" == "ftp" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/medusa_weak_passwords_${service}_${ip}.txt"
            medusa -U "$output_dir/user.lst" -P "$password_list" -h $ip -M ftp -n $port -f -O "$output_file" >> "$service_dir/medusa_$service.log" 2>&1
        done
    elif [ "$service" == "telnet" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/medusa_weak_passwords_${service}_${ip}.txt"
            medusa -U "$output_dir/user.lst" -P "$password_list" -h $ip -M telnet -n $port -f -O "$output_file" >> "$service_dir/medusa_$service.log" 2>&1
        done
    elif [ "$service" == "rdp" ]; then
        for ip in $(cat "$output_dir/live_hosts.txt"); do
            output_file="$service_dir/medusa_weak_passwords_${service}_${ip}.txt"
            medusa -U "$output_dir/user.lst" -P "$password_list" -h $ip -M rdp -n $port -f -O "$output_file" >> "$service_dir/medusa_$service.log" 2>&1
        done
    fi

    # Extract successful attempts from Medusa log and write to output file
    grep -E "ACCOUNT CHECK: \[.*\] Host: .* User: .* Password: .* \(" "$service_dir/medusa_$service.log" | awk '{print $6, $8, $10}' >> "$output_file"

    if [ -s "$output_file" ]; then
        echo "Ф Weak password check for $service with Medusa completed. Results saved to the output folder"
    else
        echo "Ф No weak passwords found for $service with Medusa."
    fi
}

# Extract live hosts
extract_live_hosts

# Check for weak passwords on SSH, FTP, TELNET, and RDP if ports are open
for service in ssh ftp telnet rdp; do
    port=0
    case $service in
        ssh)
            port=22
            ;;
        ftp)
            port=21
            ;;
        telnet)
            port=23
            ;;
        rdp)
            port=3389
            ;;
    esac

    open_hosts=$(extract_open_ports $service $port)
    if [ -n "$open_hosts" ]; then
        if [ "$scan_type" == "Basic" ]; then
            check_weak_passwords_hydra $service $port
        else
            check_weak_passwords_hydra $service $port
            check_weak_passwords_medusa $service $port
        fi
    else
        echo "Ф No open ports found for $service."
    fi
done

# Zip the output directory
zip_name="scan_results_${output_dir}.zip"
echo "Ф Archiving results to $zip_name..."
zip -r "$zip_name" "$output_dir" > /dev/null
echo "Ф Results archived in $zip_name"

# End of script
echo "Ф All tasks completed. Results saved in $output_dir."
echo "Summary of findings can be found in $scan_log"
