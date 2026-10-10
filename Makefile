PREFIX  ?= /usr/local
BINDIR  := $(PREFIX)/bin
UNITDIR := /etc/systemd/system

SVC := ipsum2nft.service
NSVC := ipsum2nft-notify.service
TMRS := ipsum2nft.timer ipsum2nft-boot.timer

.PHONY: install uninstall

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 ipsum2nft.py $(DESTDIR)$(BINDIR)/ipsum2nft
	install -d $(DESTDIR)/etc
	@[ -e $(DESTDIR)/etc/ipsum2nft.conf ] || install -m 0600 ipsum2nft.conf.example $(DESTDIR)/etc/ipsum2nft.conf
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 $(SVC) $(NSVC) $(DESTDIR)$(UNITDIR)/
	install -m 0644 $(TMRS) $(DESTDIR)$(UNITDIR)/
	@echo "Installed:"
	@echo "  $(DESTDIR)$(BINDIR)/ipsum2nft"
	@echo "  $(DESTDIR)/etc/ipsum2nft.conf  (only if absent; update + daemon options)"
	@echo "  $(DESTDIR)$(UNITDIR)/$(SVC)"
	@echo "  $(DESTDIR)$(UNITDIR)/$(NSVC)  (only when using [nflog] group)"
	@echo "  $(addprefix $(DESTDIR)$(UNITDIR)/,$(TMRS))"
	@echo "Next steps (as root):"
	@echo "  systemctl daemon-reload"
	@echo "  systemctl enable --now $(TMRS)"
	@echo "  # optional, for NFLOG hit notifications:"
	@echo "  #   edit /etc/ipsum2nft.conf  ([smtp]/[mail] sections)"
	@echo "  #   systemctl enable --now $(NSVC)"

uninstall:
	-systemctl disable --now $(TMRS) $(NSVC)
	rm -f $(BINDIR)/ipsum2nft $(UNITDIR)/$(SVC) $(UNITDIR)/$(NSVC) $(addprefix $(UNITDIR)/,$(TMRS))
	-systemctl daemon-reload
