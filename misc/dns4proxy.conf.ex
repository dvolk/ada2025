secret_key: your_key_here

txt_records:
  '_acme-challenge.machine.ada.oxfordfun.com.': '9ihDbjYfTExAYeDs4DBUeuTo18KBzwvTEjUnSwd32-c'
  '_acme-challenge.www.machine.ada.oxfordfun.com.': '9ihDbjxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

networks:
  - name: stfc cloud internal ips
    resolved_networks:
      - 172.16.104.0/21
      - 172.16.114.0/24
      - 172.16.112.0/23
      - 172.16.100.0/22
    direct_networks:
      - 172.16.104.0/21
      - 172.16.114.0/24
      - 172.16.112.0/23
      - 172.16.100.0/22
      - 130.246.0.0/16
    proxy_ips:
      - 130.246.212.136

  - name: imperial cloud external ips
    resolved_networks:
      - 146.179.0.0/16
    direct_networks:
      - 0.0.0.0/0
    proxy_ips: []