#!/bin/bash

# example: bash occurrence.sh $(find $(pwd) -name "*pcap")
# $@ here should be raw .pcap files
# please use it under the same dir with those .pcap files

for file in "$@"; do
    echo "========== $file  ========="
    tshark -r "$file" | grep response | awk '{print $NF}' > "${file}_result.txt"
    sort -u "${file}_result.txt" > "${file}_unique.txt"
    while read -r ip; do
	echo "$(grep -c "$ip" "${file}_result.txt") $ip" | tee -a "${file}_occ.txt"
    done < "${file}_unique.txt"
done

# compress the result
zip -r occ.zip "$(find "$(pwd)" -name "*pcap_occ.txt")"
