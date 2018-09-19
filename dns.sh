#!/bin/bash

# non_chinese_ip_list=(
#     "8.8.8.8"      # this is a non-chinese dns server, just for testing
#     "8.8.4.4"      # this is a non-chinese dns server, just for testing

#     # TODO: fix the bug that 1.1.1.1 sometimes could not be reached
#     # out, making it treated as not a dns resolver. We now temporarily
#     # not include it as a workaround. The root problem is actually
#     # because we determine if an ip address has the DNS function by a
#     # single query. Since the ISPs may hijacking or null-routing the
#     # DNS request, a more accurate algorithm should be came up with to
#     # fix the problem.

#     #"1.1.1.1" # this is a non-chinese dns server, just for testing
#     "129.42.17.103"
#     "129.42.17.106"
#     "109.49.18.103"
# )

# when outside of China (beyond the GFW), since DNS poisoing is
# two-way. Simple use a Chinese IP that does not have DNS resolving or
# forwarding function. Chinese IP ranges can be found here:
# https://lite.ip2location.com/china-ip-address-ranges
# chinese_ip_list=(
#     "202.107.249.28"
#     "60.245.128.2"
#     "60.247.10.18"
#     "114.114.115.119"           # this is a chinese dns server, just for testing
#     "66.78.32.134"
#     "103.22.95.254"
#     "180.76.76.76"              # this is a chinese dns server, just for testing
#     "93.119.20.1"
#     "202.107.249.27"
#     "210.2.4.8"                 # this is a chinese dns server, just for testing
#     "202.107.249.29"
#     "202.107.249.30"
#     "202.107.249.31"
# )


# censored_domain_list=(
#     "www.chinadigitaltimes.net"
#     "www.youtube.com"
#     "www.facebook.com"
#     "www.twitter.com"
# )

## ONLY work for bash 4.x
readarray -t non_chinese_ip_list < non_chinese_ip.txt
readarray -t chinese_ip_list < chinese_ip.txt
readarray -t censored_domain_list < blacklist.txt

not_a_dns_resolver_set=()

uncensored_domain="www.baidu.com"

position_to_gfw(){
    echo "Are you behind the GFW?"
    select option in "I am behind GFW." "I am beyond GFW." "I don't know."; do
        case $option in
            # when in China, or has routed all the traffic to China
            "I am behind GFW.")
                is_behind_gfw=true
                break;;
            "I am beyond GFW.")
                is_behind_gfw=false
                break;;
            "I don't know.")
                echo "Trying to decide automatically..."
                # one should be able to ping www.google.com when beyond GFW
                ping -w 3 www.google.com
                if [ $? -ne 0 ]; then
                    echo "It seems you are behind the GFW."
                    is_behind_gfw=true
                else
                    echo "It seems you are NOT behind the GFW."
                    is_behind_gfw=false
                fi
                break;;
            *)
                echo "Unknown option. Hit enter to see all the options again."
        esac
    done

}

query_not_dns_resolver_set(){
    echo "/=========== Selecting a list of IPs that satisefy: =============\\"
    echo "|         1. It is an IP on the opposite side of the GFW         |"
    echo "|         2. It has NO DNS resolving or forwarding function      |"
    echo "\================================================================/"

    if [ "$is_behind_gfw" == true ]; then     # if behind_gfw
        ip_list=(${non_chinese_ip_list[@]})
    else
        ip_list=(${chinese_ip_list[@]})
    fi

    for potential_dns in "${ip_list[@]}"; do
        echo "--- Checking DNS function of $potential_dns ---"
        # TODO: do different type queries eg. AAA
        response=$(nslookup -timeout=5 -type=A "$uncensored_domain" "$potential_dns")
        if [ $? -ne 0 ]; then
            # if timeout, then it means the ip does not have dns
            # resolving or forwarding function we can therefore safely
            # add it to the not_a_dns_resolver_set
            not_a_dns_resolver_set+=($potential_dns)
            # echo "Satisfied IP List: ${not_a_dns_resolver_set[@]}"
            echo "[*] Select: $potential_dns"
            continue
        else
            echo "[x] Discard: $potential_dns"
        fi
    done
}

# trigger_poisoned_response() requires one augument as $1 -- one specific censored domain
trigger_poisoned_response() {
    local censored_domain="$1"
    local identifier
    identifier="$(date -u +%Y-%m-%d_%H-%M-%S)_${censored_domain}"
    local result_file="${identifier}_result.txt"
    local unique_file="${identifier}_unique.txt"
    local traffic_file="${identifier}_traffic.pcap"
    # capture DNS traffic
    sudo tcpdump -i eth0 -nn -s0 port 53 -w "$traffic_file" &
    # wait for tcpdump to start
    sleep 1
    # index of dst ip list
    local index_dst_ip=0
    # count number of dst IP switching due to timeout, if the number
    # is large enough, we consider the domain name as NOT poisoned.
    local count_timeout=0
    local max_timeout=5
    # The fist $num_testing_loop loop is for determination of type 1
    # or type 2 poisoning.
    local num_testing_loop=40
    # In 2018, the value should be 4, but considering previous proper
    # value may up to 40, we set it as 10 here.  Statistical analysis
    # should be done to give the appropriate value and possibility.
    local num_assumed_type_one_result=10
    echo "==========Try to trigger poisoned DNS responses =================="
    for i in {1..100}; do
        # Optimize for Type 1 poisoning responses by counting numer of
        # unique result. If the number is relatively small, even after
        # a large amount of query, we consider the poisoning method as
        # type 1 and skip the rest of the queries to save resourse and
        # time
        if [[ $i -eq $num_testing_loop ]] && [[ $(sort -u "$result_file" | wc -l) -le $num_assumed_type_one_result ]]; then
            echo "Only $(sort -u "$result_file" | wc -l) unique result is found after $num_testing_loop quering. Mark as tyoe 1 poisoning and stop further quering."
        fi
        echo -n "--- Query $censored_domain from ${not_a_dns_resolver_set[$index_dst_ip]}: "
        response=$(nslookup -timeout=1 -type=A "$censored_domain" "${not_a_dns_resolver_set[$index_dst_ip]}")
        if [ $? -ne 0 ]; then
            count_timeout=$(expr $count_timeout + 1)
            echo ""                 # for newline formatting
            echo "[x] Time out happened. Total timeout: $count_timeout Switch non-resolver IP."
            index_dst_ip=$(expr $(expr $index_dst_ip + 1) % ${#not_a_dns_resolver_set[@]})
            if [[ $count_timeout -eq $i ]] && \
                   [[ $count_timeout -gt $max_timeout ]]; then
                echo "No fake repsonse detected in $count_timeout loops. $censored_domain may not be poinsoned." | tee -a "$result_file"
                break           # break from the loop
            fi
            continue
        else
            echo "$response" | grep -i address | tail -n 1 | sed s/Address:\ // | tee -a "$result_file"
        fi
    done

    echo "================Finished Query=============================="
    sort -u "$result_file" | tee "$unique_file"
    # stop capturing DNS traffic
    sudo pkill tcpdump
}

# while read ip; do
#     whois $ip | tee -a whois.txt
# done <unique.txt

directory="$HOME/dns_data/$(date -u +%Y-%m-%d_%H)"
mkdir -p "$directory"
cd "$directory" || exit 1

position_to_gfw
query_not_dns_resolver_set

for censored_domain in "${censored_domain_list[@]}"; do
    echo "Start quering $censored_domain"
    trigger_poisoned_response "$censored_domain"
done
