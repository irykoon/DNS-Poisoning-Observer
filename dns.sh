#!/bin/bash

non_chinese_ip_list=(
    "8.8.8.8"      # this is a non-chinese dns server, just for testing
    "8.8.4.4"      # this is a non-chinese dns server, just for testing

    # TODO: fix the bug that 1.1.1.1 sometimes could not be reached
    # out, making it treated as not a dns resolver. We now temporarily
    # not include it as a workaround.

    #"1.1.1.1" # this is a non-chinese dns server, just for testing
    "129.42.17.103"
    "129.42.17.106"
    "109.49.18.103"
)

#nslookup -type=A www.google.com 129.42.17.103 | grep -i address | tail -n 1

# when outside of China (beyond the GFW), since DNS poisoing is
# two-way. Simple use a Chinese IP that does not have DNS resolving or
# forwarding function. Chinese IP ranges can be found here:
# https://lite.ip2location.com/china-ip-address-ranges
chinese_ip_list=(
    "202.107.249.28"
    "60.245.128.2"
    "60.247.10.18"
    "114.114.115.119"           # this is a chinese dns server, just for testing
    "66.78.32.134"
    "103.22.95.254"
    "180.76.76.76"              # this is a chinese dns server, just for testing
    "93.119.20.1"
    "202.107.249.27"
    "210.2.4.8"                 # this is a chinese dns server, just for testing
    "202.107.249.29"
    "202.107.249.30"
    "202.107.249.31"
)

not_a_dns_resolver_set=()

censored_domain_list=(
    "www.youtube.com"
    "www.facebook.com"
    "www.twitter.com"
)
uncensored_domain="www.baidu.com"

mv result.txt result.txt.backup
mv unique.txt unique.txt.backup
mv domain.txt domain.txt.backup

position_to_gfw(){
    echo "Are you behind the GFW?"
    select option in "I am behind GFW." "I am beyond GFW." "I don't know."; do
        case $option in
            # when in China, or has routed all the traffic to China
            "I am behind GFW.")
                is_behind_gfw=true
                break;;
            "I am beyond GFW.")
                is_beyond_gfw=false
                break;;
            "I don't know.")
                echo "Trying to decide automatically..."
                ping -w 3 www.google.com # one should be able to ping www.google.com when beyond GFW
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

    if [ $is_behind_gfw ]; then     # if behind_gfw
        ip_list=(${non_chinese_ip_list[@]})
    else
        ip_list=(${chinese_ip_list[@]})
    fi

    for potential_dns in "${ip_list[@]}"; do
        echo "--- Checking DNS function of $potential_dns ---"
        # TODO: do different type queries eg. AAA
        response=$(nslookup -timeout=5 -type=A $uncensored_domain $potential_dns)
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
    count=0
    echo "==========Try to trigger poisoned DNS responses =================="
    for i in {1..100}; do
        echo -n "--- Query $censored_domain from ${not_a_dns_resolver_set[$count]}: "
        response=$(nslookup -timeout=1 -type=A $censored_domain ${not_a_dns_resolver_set[$count]})
        if [ $? -ne 0 ]; then
            echo ""                 # for newline formatting
            echo "[x] Time out happened. Switch to query from another IP."
            count=$(expr $(expr $count + 1) % ${#not_a_dns_resolver_set[@]})
            continue
            # $not_a_dns_resolver="${not_a_dns_resolver_set[$count]}"
        else
            echo "$response" | grep -i address | tail -n 1 | sed s/Address:\ // | tee -a result.txt
        fi
    done

    echo "================Finished Query=============================="
    sort -u result.txt | tee unique.txt
}

# while read ip; do
#     whois $ip | tee -a whois.txt
# done <unique.txt
position_to_gfw
query_not_dns_resolver_set

for censored_domain in "${censored_domain_list[@]}"; do
    echo "Start quering $censored_domain" | tee -a result.txt
    trigger_poisoned_response "$censored_domain"
done
