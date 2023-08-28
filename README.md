# ABS

Non-intrusive access monitoring scenario using attribute based signatures.

## Requirements

* **Python 3.6** (verified to work) or possibly newer (untested) with the included base libraries
* Libraries **charm-crypto**, **netfilterqueue** and **scapy** and their respective requirements
* Install charm-crypto in linux: https://zhuanlan.zhihu.com/p/447934026
* sudo apt install libnfnetlink-dev libnetfilter-queue-dev(Install **netfilterqueue**)

## Fix
* There are two issues in the PolicyParser of charm-crypto.
  1.It will parse “age AND test” and generate nodes like 'AGE' and 'TEST', which will cause KeyError in python.
  2.It will parse "AGE<18" to "AGE" “<” “18”.
* Solution
  1. charm/toolbox/node.py   Class BinNode  func _init_   delete upper().
     line 24:   self.attribute = value
  2. charm/toolbox/policy_tree.py  getBNF  add Combine to leafConditional.
     line 58: leafConditional = Combine(Word(alphanums) + BinOperator + Word(nums)).setParseAction( parseNumConditional) 
## Usage

1. Configure addons by editing ABSSetup.py (JSON support may come later)
2. Run `$ sudo iptables -A OUTPUT -p tcp -j NFQUEUE` to send packets to the NFQUEUE handler.
3. Start the server process via `$ sudo python3.6 ABSSentinel.py` which gives you the port number (host is the IP of the machine running it).
4. Start the client process as `$ sudo python3.6 ABSClient.py serverhost serverport networkalias` where:
* `serverhost` and `serverport` are self-explanatory.
* `networkalias` is the IP address representing the client in the packets sent to/from the client. This is for enabling NAT support.
5. When finished, stop the processes via Ctrl-C and run `$ sudo iptables -D OUTPUT -p tcp -j NFQUEUE` to stop the packet handler
