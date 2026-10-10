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
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 $(SVC) $(NSVC) $(DESTDIR)$(UNITDIR)/
	install -m 0644 $(TMRS) $(DESTDIR)$(UNITDIR)/
	@echo "Installed:"
	@echo "  $(DESTDIR)$(BINDIR)/ipsum2nft"
	@echo "  $(DESTDIR)$(UNITDIR)/$(SVC)"
	@echo "  $(DESTDIR)$(UNITDIR)/$(NSVC)  (only when using --log-group)"
	@echo "  $(addprefix $(DESTDIR)$(UNITDIR)/,$(TMRS))"
	@echo "Next steps (as root):"
	@echo "  systemctl daemon-reload"
	@echo "  systemctl enable --now $(TMRS)"
	@echo "  # optional, for --log-group hit notifications:"
	@echo "  #   cp ipsum2nft.conf.example /etc/ipsum2nft.conf  (edit, chmod 0600)"
	@echo "  #   systemctl enable --now $(NSVC)"

uninstall:
	-systemctl disable --now $(TMRS) $(NSVC)
	rm -f $(BINDIR)/ipsum2nft $(UNITDIR)/$(SVC) $(UNITDIR)/$(NSVC) $(addprefix $(UNITDIR)/,$(TMRS))
	-systemctl daemon-reload
