obj-m += network_counter.o

KERN_VER = $(shell uname -r)
PWD = $(shell pwd)

all: prepare

build:
	make -C /lib/modules/$(KERN_VER)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KERN_VER)/build M=$(PWD) clean
	rm -f $(PWD)/network_counter.ko
	rm -f $(PWD)/network_counter.gz

test:
	make -C /lib/modules/$(KERN_VER)/build M=$(PWD) install

prepare: build
	rm -f $(PWD)/network_counter.ko.gz
	gzip -c $(PWD)/network_counter.ko > $(shell pwd)/network_counter.ko.gz

install:
	cp $(PWD)/network_counter.ko.gz /lib/modules/$(KERN_VER)/kernel/net/ipv4/netfilter/network_counter.ko.gz
	@if [ -z $$(cat /lib/modules/$(KERN_VER)/modules.builtin | grep network_counter) ]; then \
		echo "Registering the module..."; \
		echo kernel/net/ipv4/netfilter/network_counter.ko >> /lib/modules/$(KERN_VER)/modules.builtin; \
	fi;

uninstall:
	sed -i '/network_counter.ko/d' /lib/modules/$(KERN_VER)/modules.builtin
