all:
	# create pri key & certificate
	openssl genrsa -out ca.key 2048
	openssl rand -writerand /home/csc2023/.rnd
	openssl req -new -x509 -days 1096 -key ca.key -out ca.crt -subj '/C=TW/O=NYCU/CN=tsc.Hsinchu'
	# open router
	sudo sysctl -w net.ipv4.ip_forward=1 
	# set iptables rules 
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
	# create logdir
	mkdir -p ./tmp
	mkdir -p ./tmp/logdir

clean:
	rm -f ca.key
	rm -f ca.crt
	rm -rf ./tmp/
	
